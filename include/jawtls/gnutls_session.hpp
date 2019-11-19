#pragma once

#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <vector>

#include <gnutls/dtls.h>

#include <iostream> // TODO(aalbers): Remove

#include "certificate.hpp" // TODO(albers): Forward declare and create fingerprint.hpp

namespace jawtls {
namespace impl {

static gnutls_certificate_credentials_t* create_credentials() {
  auto creds = new gnutls_certificate_credentials_t;
  check_result_and_throw(gnutls_certificate_allocate_credentials(creds), "gnutls_certificate_allocate_credentials");
  return creds;
}

static void delete_credentials(gnutls_certificate_credentials_t* creds) {
  gnutls_certificate_free_credentials(*creds);
  delete creds;
}

using credentials = std::unique_ptr<gnutls_certificate_credentials_t, decltype(&delete_credentials)>;

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
    , _cred{create_credentials(), delete_credentials}
    , _encrypted_out{std::move(encrypted_out)}
    , _unencrypted_out{std::move(unencrypted_out)}
    , _verify_func{std::move(verify_func)}
    {
      std::cout << this << " constructor " << (type == session::role::client ? "client" : "server" ) << std::endl;
      check_result_and_throw(gnutls_certificate_set_x509_key(*_cred, _cert._self->_crt.get(), 1, *_cert._self->_key), "gnutls_certificate_set_x509_key");
      gnutls_certificate_set_verify_function(*_cred, certificate_callback);
      
      unsigned int flags = GNUTLS_NONBLOCK | GNUTLS_DATAGRAM | (type == session::role::client ? GNUTLS_CLIENT : GNUTLS_SERVER);
      check_result_and_throw(gnutls_init(&_session, flags), "gnutls_init");
      
      const char *priorities = "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128";
      const char *err_pos = NULL;
      check_result_and_throw(gnutls_priority_set_direct(_session, priorities, &err_pos), "gnutls_priority_set_direct");
      
      gnutls_session_set_ptr(_session, this);
      gnutls_transport_set_ptr(_session, this);
      gnutls_transport_set_push_function(_session, write_callback);
      gnutls_transport_set_pull_function(_session, read_callback);
      gnutls_transport_set_pull_timeout_function(_session, timeout_callback);
      
      check_result_and_throw(gnutls_credentials_set(_session, GNUTLS_CRD_CERTIFICATE, *_cred), "gnutls_credentials_set");
    }
    ~model() {
      std::cout << this << " destructor" << std::endl;
    }
    
    executor _e;
    const role _type;
    certificate _cert;
    credentials _cred;
    encrypted_data_out_func _encrypted_out;
    unencrypted_data_out_func _unencrypted_out;
    verify_fingerprint_func _verify_func;
    std::queue<std::function<void()>> _post_handshake_actions;
    std::string _buffer;
    gnutls_session_t _session;
    
    void do_post_handshake_actions() {
      std::cout << this << " do_post_handshake_actions" << std::endl;
      while (!_post_handshake_actions.empty()) {
        _post_handshake_actions.front()();
        _post_handshake_actions.pop();
      }
    }
    
    void operator()(encrypted_payload payload) {
      _e([this, strong_this = shared_from_this(), payload = std::move(payload)]{
        std::cout << this << " notify encrypted " << payload.data.size() << std::endl;
        _buffer = std::move(payload.data);
        std::vector<char> buffer(_buffer.size());
        ssize_t ret = gnutls_record_recv(_session, buffer.data(), buffer.size());
        if (ret == GNUTLS_E_AGAIN) return;
        if (ret == GNUTLS_E_UNAVAILABLE_DURING_HANDSHAKE || ret == GNUTLS_E_REHANDSHAKE) {
          std::cout << this << " doing handshake instead" << std::endl;
          int code = gnutls_handshake(_session);
          std::cout << this << " gnutls_handshake encrypted_payload:" << code << std::endl;
          if (code == 0) do_post_handshake_actions();
          return;
        }
        std::cout << this << " gnutls_record_recv:" << ret << std::endl;
        buffer.resize(ret);
        _unencrypted_out(unencrypted_payload{std::string{std::begin(buffer), std::end(buffer)}});
      });
    }
    void operator()(unencrypted_payload payload) {
      _e([this, strong_this = shared_from_this(), payload = std::move(payload)]{
        auto action = [this, strong_this = std::move(strong_this), payload = std::move(payload)]{
          ssize_t ret = gnutls_record_send(_session, payload.data.data(), payload.data.size());
          if (ret == GNUTLS_E_UNAVAILABLE_DURING_HANDSHAKE) return false;
          std::cout << this << " ret: " << ret << std::endl;
          if (static_cast<size_t>(ret) != payload.data.size()) throw std::runtime_error("gnutls_record_send");
          return true;
        };
        if (!action()) _post_handshake_actions.push(std::move(action));
      });
    }
    void handshake() {
      _e([this, strong_this = shared_from_this()]{
        if (_type == role::client) {
          std::cout << this << " start handshake" << std::endl;
          int code = gnutls_handshake(_session);
          std::cout << this << " end handshake:" << code << std::endl;
        } else {
          std::cout << this << " start rehandshake" << std::endl;
          int code = gnutls_rehandshake(_session);
          std::cout << this << " end rehandshake:" << code << std::endl;
        }
      });
    }
    static int certificate_callback(gnutls_session_t session) {
        model* s = static_cast<model*>(gnutls_session_get_ptr(session));
        
        if (!s->_verify_func) return GNUTLS_E_SUCCESS;
        if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) return GNUTLS_E_CERTIFICATE_ERROR;

        unsigned int count = 0;
        const gnutls_datum_t* array = gnutls_certificate_get_peers(session, &count);
        if (!array || count == 0) return GNUTLS_E_CERTIFICATE_ERROR;
        
        gnutls_x509_crt_t crt;
        check_result_and_throw(gnutls_x509_crt_init(&crt), "gnutls_x509_crt_init");
        int ret = gnutls_x509_crt_import(crt, &array[0], GNUTLS_X509_FMT_DER);
        if (ret != GNUTLS_E_SUCCESS) {
          gnutls_x509_crt_deinit(crt);
          return GNUTLS_E_CERTIFICATE_ERROR;
        }

        std::string fingerprint = certificate::make_fingerprint(&crt);
        gnutls_x509_crt_deinit(crt);
        std::cout << s << " verifying: " << fingerprint << std::endl;
        return s->_verify_func(fingerprint) ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;
      }
      static ssize_t write_callback(gnutls_transport_ptr_t ptr, const void *data, size_t len) {
        model* s = static_cast<model*>(ptr);
        std::cout << s << " write_callback(" << len << ")" << std::endl;
        if (len > 0) {
          auto b = reinterpret_cast<const char *>(data);
          s->_e([s, strong_s = s->shared_from_this(), payload = session::encrypted_payload{std::string{b, b + len}}]{
            s->_encrypted_out(std::move(payload));
          });
        }
        gnutls_transport_set_errno(s->_session, 0);
        return ssize_t(len);
      }
      static ssize_t read_callback(gnutls_transport_ptr_t ptr, void *data, size_t maxlen) {
        model* s = static_cast<model*>(ptr);
        std::cout << s << " read_callback(" << s->_buffer.size() << "," << maxlen << ")" << std::endl;
        if (s->_buffer.empty()) {
          std::cout << s << " empty" << std::endl;
          errno = EWOULDBLOCK;
          return -1;
        }
        ssize_t len = std::min(maxlen, s->_buffer.size());
        std::cout << s << " len " << len << std::endl;
        std::memcpy(data, s->_buffer.data(), len);
        gnutls_transport_set_errno(s->_session, 0);
        return len;
      }
      static int timeout_callback(gnutls_transport_ptr_t ptr, unsigned int ms) {
        model* s = static_cast<model*>(ptr);
        std::cout << s << " timeout: " << ms << std::endl;
        return 1; // So read_callback is called
      }
  };
  session(std::shared_ptr<model> self) : _self{std::move(self)} {}
  std::shared_ptr<model> _self;
};

} // namespace impl
} // namespace jawtls
