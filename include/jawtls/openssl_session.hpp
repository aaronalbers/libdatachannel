#pragma once

#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <vector>

#include <iostream> // TODO(aalbers): Remove

#include "certificate.hpp" // TODO(albers): Forward declare and create fingerprint.hpp

namespace jawtls {
namespace impl {

static SSL_CTX* create_ctx(const SSL_METHOD* method) {
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) throw_error(ERR_get_error(), "SSL_CTX_new");
  return ctx;
}

static void delete_ctx(SSL_CTX* ctx) {
  SSL_CTX_free(ctx);
}

static BIO* create_bio() {
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) throw_error(ERR_get_error(), "BIO_new");
  return bio;
}

static void delete_bio(BIO* bio) {
  BIO_free(bio);
}

static SSL* create_ssl(SSL_CTX* ctx) {
  SSL* ssl = SSL_new(ctx);
  if (!ssl) throw_error(ERR_get_error(), "SSL_new");
  return ssl;
}

static void delete_ssl(SSL* ssl) {
  SSL_free(ssl);
}

using ssl_ctx = std::unique_ptr<SSL_CTX, decltype(&delete_ctx)>;
using bio_mem = std::unique_ptr<BIO, decltype(&delete_bio)>;
using ssl_t = std::unique_ptr<SSL, decltype(&delete_ssl)>;

class session final {
  friend bool operator==(const session& lhs, const session& rhs) { return lhs._self == rhs._self; }
public:
  struct encrypted_payload {
    std::string data;
  };
  struct unencrypted_payload {
    std::string data;
  };
  using fingerprint = certificate::fingerprint;
  using encrypted_data_out_func = std::function<void(encrypted_payload)>;
  using unencrypted_data_out_func = std::function<void(unencrypted_payload)>;
  using verify_fingerprint_func = std::function<bool(const fingerprint&)>;
  using executor = std::function<void(std::function<void()>)>;
  enum class role { server, client };
  static session make(executor e,
                      role type,
                      certificate cert,
                      encrypted_data_out_func encrypted_out,
                      unencrypted_data_out_func unencrypted_out,
                      verify_fingerprint_func verify_func) {
    auto s = std::make_shared<model>(std::move(e),
                                     type,
                                     std::move(cert),
                                     std::move(encrypted_out),
                                     std::move(unencrypted_out),
                                     std::move(verify_func));
    if (type == role::client) s->handshake();
    return s;
  }
  
  void operator()(encrypted_payload payload) { (*_self)(std::move(payload)); }
  void operator()(unencrypted_payload payload) { (*_self)(std::move(payload)); }
  
private:
  static const SSL_METHOD* select_method(role type) {
    switch (type) {
      case role::client: return SSLv23_client_method();
      case role::server: return SSLv23_server_method();
    }
  }
  static int get_data_index() {
    static int data_index = SSL_get_ex_new_index(0, (void*)"session ptr index", NULL, NULL, NULL);
    return data_index;
  }
  struct model : std::enable_shared_from_this<model> {
    model(executor e,
          role type,
          certificate cert,
          encrypted_data_out_func encrypted_out,
          unencrypted_data_out_func unencrypted_out,
          verify_fingerprint_func verify_func)
    : _e{std::move(e)}
    , _type{type}
    , _cert{std::move(cert)}
    , _ctx{create_ctx(select_method(_type)), delete_ctx}
    , _ssl{create_ssl(_ctx.get()), delete_ssl}
    , _encrypted_out{std::move(encrypted_out)}
    , _unencrypted_out{std::move(unencrypted_out)}
    , _verify_func{std::move(verify_func)}
    {
      std::cout << this << " constructor " << (type == session::role::client ? "client" : "server" ) << std::endl;
      check_result_and_throw(SSL_use_certificate(_ssl.get(), _cert._self->_crt.get()), "SSL_use_certificate");
      check_result_and_throw(SSL_use_PrivateKey(_ssl.get(), _cert._self->_key.get()), "SSL_use_PrivateKey");
      check_result_and_throw(SSL_check_private_key(_ssl.get()), "SSL_check_private_key");
      //check_result_and_throw(SSL_set_cipher_list(_ssl.get(), "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"), "SSL_CTX_set_cipher_list");
      
      SSL_set_ex_data(_ssl.get(), get_data_index(), this);
      
      SSL_set_verify(_ssl.get(), SSL_VERIFY_PEER, certificate_callback);
      SSL_set_info_callback(_ssl.get(), info_callback);
      
      /* Recommended to avoid SSLv2 & SSLv3 */
      SSL_set_options(_ssl.get(), SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
      
      if (_type == role::server) {
        SSL_set_accept_state(_ssl.get());
      } else {
        SSL_set_connect_state(_ssl.get());
      }
      
      bio_mem wbio{create_bio(), delete_bio};
      bio_mem rbio{create_bio(), delete_bio};
      _wbio = wbio.release(); // Freed with _ssl after SSL_set_bio
      _rbio = rbio.release(); // Freed with _ssl after SSL_set_bio
      SSL_set_bio(_ssl.get(), _rbio, _wbio);
    }
    ~model() {
      std::cout << this << " destructor" << std::endl;
    }
    
    executor _e;
    const role _type;
    certificate _cert;
    BIO* _wbio = nullptr;
    BIO* _rbio = nullptr;
    ssl_ctx _ctx;
    ssl_t _ssl;
    encrypted_data_out_func _encrypted_out;
    unencrypted_data_out_func _unencrypted_out;
    verify_fingerprint_func _verify_func;
    bool _doing_handshake{true};
    std::queue<std::function<void()>> _post_handshake_actions;
    
    void do_post_handshake_actions() {
      std::cout << this << " do_post_handshake_actions" << std::endl;
      while (!_post_handshake_actions.empty()) {
        _post_handshake_actions.front()();
        _post_handshake_actions.pop();
      }
    }
    
    void queue_encrypted_out(encrypted_payload payload) {
      _e([this, strong_this = shared_from_this(), payload = std::move(payload)]{
        _encrypted_out(std::move(payload));
      });
    }
    
    enum class ssl_status {
      OK,
      WANT_IO,
      FAIL
    };

    static ssl_status get_sslstatus(SSL* ssl, int n) {
      switch (SSL_get_error(ssl, n)) {
        case SSL_ERROR_NONE:
          return ssl_status::OK;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          return ssl_status::WANT_IO;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        default:
          return ssl_status::FAIL;
      }
    }
    
    static void info_callback(const SSL* ssl, int where, int ret) {
      model* s = static_cast<model*>(SSL_get_ex_data(ssl, get_data_index()));
      if (where == SSL_CB_HANDSHAKE_START) {
        std::cout << s << " report handshake start: " << ret << std::endl;
        s->_doing_handshake = true;
      } else if (where == SSL_CB_HANDSHAKE_DONE) {
        std::cout << s << " report handshake end: " << ret << std::endl;
        s->_doing_handshake = false;
        s->do_post_handshake_actions();
      }
    }
    
    static int certificate_callback(int preverify_ok, X509_STORE_CTX* ctx) {
      X509* crt = X509_STORE_CTX_get_current_cert(ctx);
      SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
      model* s = static_cast<model*>(SSL_get_ex_data(ssl, get_data_index()));
      std::cout << s << " " << crt <<  " verify_callback: " << preverify_ok << std::endl;
      if (!s->_verify_func) return 1;
      std::string fingerprint = certificate::make_fingerprint(crt);
      std::cout << s << " verifying: " << fingerprint << std::endl;
      return s->_verify_func(fingerprint);
    }
    
    ssl_status do_ssl_handshake() {
      int n = SSL_do_handshake(_ssl.get());
      ssl_status status = get_sslstatus(_ssl.get(), n);

      /* Did SSL request to write bytes? */
      if (status == ssl_status::WANT_IO) {
        char buf[64];
        do {
          n = BIO_read(_wbio, buf, sizeof(buf));
          if (n > 0) {
            queue_encrypted_out(encrypted_payload{std::string{buf, static_cast<size_t>(n)}});
          } else if (!BIO_should_retry(_wbio)) {
            return ssl_status::FAIL;
          }
        } while (n > 0);
      }

      return status;
    }
    
    int on_read_cb(const char* src, size_t len) {
      char buf[64];
      ssl_status status;
      int n;

      while (len > 0) {
        n = BIO_write(_rbio, src, len);

        if (n <= 0) return -1; /* assume bio write failure is unrecoverable */

        src += n;
        len -= n;

        if (!SSL_is_init_finished(_ssl.get())) {
          if (do_ssl_handshake() == ssl_status::FAIL) return -1;
          if (!SSL_is_init_finished(_ssl.get())) return 0;
        }

        /* The encrypted data is now in the input bio so now we can perform actual
         * read of unencrypted data. */

        do {
          n = SSL_read(_ssl.get(), buf, sizeof(buf));
          if (n > 0) {
            _unencrypted_out(unencrypted_payload{std::string{buf, static_cast<size_t>(n)}});
          }
        } while (n > 0);

        status = get_sslstatus(_ssl.get(), n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
         * renegotiation. */
        if (status == ssl_status::WANT_IO) {
          do {
            n = BIO_read(_wbio, buf, sizeof(buf));
            if (n > 0) {
              queue_encrypted_out(encrypted_payload{std::string{buf, static_cast<size_t>(n)}});
            } else if (!BIO_should_retry(_wbio)) {
              return -1;
            }
          } while (n > 0);
        }

        if (status == ssl_status::FAIL) return -1;
      }

      return 0;
    }
    
    int on_write_cb(const char* src, size_t len) {
      if (!SSL_is_init_finished(_ssl.get())) return 0;
      
      char buf[64];
      ssl_status status;

      while (len > 0) {
        int n = SSL_write(_ssl.get(), src, len);
        status = get_sslstatus(_ssl.get(), n);

        if (n > 0) {
          /* consume the waiting bytes that have been used by SSL */
          src += n;
          len -= n;

          /* take the output of the SSL object and queue it for socket write */
          do {
            n = BIO_read(_wbio, buf, sizeof(buf));
            if (n > 0) {
              queue_encrypted_out(encrypted_payload{std::string{buf, static_cast<size_t>(n)}});
            } else if (!BIO_should_retry(_wbio)) {
              return -1;
            }
          } while (n > 0);
        }

        if (status == ssl_status::FAIL) return -1;

        if (n == 0) break;
      }
      return 0;
    }
    
    void operator()(encrypted_payload payload) {
      _e([this, strong_this = shared_from_this(), payload = std::move(payload)]{
        std::cout << this << " notify encrypted " << payload.data.size() << std::endl;
        on_read_cb(payload.data.data(), payload.data.size());
      });
    }
    void operator()(unencrypted_payload payload) {
      _e([this, strong_this = shared_from_this(), payload = std::move(payload)]{
        std::cout << this << " notify unencrypted " << payload.data.size() << std::endl;
        auto action = [this, strong_this = std::move(strong_this), payload = std::move(payload)]{
          on_write_cb(payload.data.data(), payload.data.size());
        };
        if (_doing_handshake) {
          _post_handshake_actions.push(std::move(action));
        } else {
          action();
        }
      });
    }
    void handshake() {
      _e([this, strong_this = shared_from_this()]{
        if (_type == role::server) return;
        do_ssl_handshake();
      });
    }
  };
  session(std::shared_ptr<model> self) : _self{std::move(self)} {}
  std::shared_ptr<model> _self;
};

} // namespace impl
} // namespace jawtls
