#pragma once

#include <memory>
#include <string>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

namespace jawtls {
namespace impl {

[[noreturn]] static void throw_error(const std::string& message) {
  throw std::runtime_error(message);
}

[[noreturn]] static void throw_error(int result, const std::string& message) {
  throw_error(message + ": " + ERR_reason_error_string(result));
}

static void check_result_and_throw(int result, const std::string& message) {
  if (result == 1) return;
  throw_error(result, message);
}

struct init_t {
  init_t() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
  }
  ~init_t() {
    // https://wiki.openssl.org/index.php/Library_Initialization#Cleanup
    FIPS_mode_set(0);
    //ENGINE_cleanup();
    //CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    //ERR_remove_state();
    ERR_free_strings();
  }
};
static init_t init_library() {
  return {};
}

static X509* create_crt() {
  X509* crt = X509_new();
  if (!crt) throw_error(ERR_get_error(), "X509_new");
  return crt;
}

static void delete_crt(X509* crt) {
  X509_free(crt);
}

static EVP_PKEY* create_privkey() {
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw_error(ERR_get_error(), "EVP_PKEY_new");
  return pkey;
}

static void delete_privkey(EVP_PKEY* privkey) {
  EVP_PKEY_free(privkey);
}

using x509_crt = std::unique_ptr<X509, decltype(&delete_crt)>;
using x509_key = std::unique_ptr<EVP_PKEY, decltype(&delete_privkey)>;

class session; // Forward Declare

class certificate final {
  friend class session;
  friend bool operator==(const certificate& lhs, const certificate& rhs) { return lhs._self == rhs._self; }
public:
  struct hasher {
     size_t operator()(const certificate& c) const {
        return std::hash<std::shared_ptr<const void>>{}(c._self);
     }
  };
  using fingerprint = std::string;
  static certificate make_self_signed(const std::string& common_name) {
    static init_t init_once = init_library();
    
    x509_crt crt{create_crt(), delete_crt};
    x509_key privkey{create_privkey(), delete_privkey};
    
    /* Generate the RSA key and assign it to the pkey. The `rsa` will be freed when we free the pkey. */
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    check_result_and_throw(EVP_PKEY_assign_RSA(privkey.get(), rsa), "EVP_PKEY_assign_RSA");
                                                                              
    /* Set the serial number. Some browsers don't accept the default one (0).*/
    ASN1_INTEGER_set(X509_get_serialNumber(crt.get()), 1);

    /* The certificate is valid until one year from now. */
    X509_gmtime_adj(X509_get_notBefore(crt.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(crt.get()), 31536000L);

    /* Set the public key for our certificate */
    X509_set_pubkey(crt.get(), privkey.get());

    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(crt.get());
    if (!name) throw_error("X509_get_subject_name");

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"jawtls", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)common_name.data(), -1, -1, 0);

    /* Set the issuer name. */
    X509_set_issuer_name(crt.get(), name);

    /* Sign the certificate with our key. */
    if (!X509_sign(crt.get(), privkey.get(), EVP_sha1())) throw_error("X509_sign");
    
    return std::make_shared<const model>(std::move(crt), std::move(privkey));
  }
  static fingerprint make_fingerprint(X509* crt) {
    uint8_t fingerprint[8192];
    char fingerprint_string[8192];
    uint32_t len = sizeof(fingerprint);
    uint32_t buflen = sizeof(fingerprint_string);
    
    memset(fingerprint, 0x00, sizeof(fingerprint));
    memset(fingerprint_string, 0x00, sizeof(fingerprint_string));
    
    check_result_and_throw(X509_digest(crt, EVP_sha256(), fingerprint, &len), "X509_digest");
    
    for (uint32_t i = 0, pos = 0; i < len; ++i) {
      if (i > 0) {
        pos += snprintf(fingerprint_string + pos, buflen - pos, ":");
      }
      pos += snprintf(fingerprint_string + pos, buflen - pos, "%02X", fingerprint[i]);
    }

    return fingerprint_string;
  }
  static fingerprint make_fingerprint(const certificate& cert) {
    return make_fingerprint(cert._self->_crt.get());
  }
private:
  struct model {
    model(x509_crt crt, x509_key key)
    : _crt{std::move(crt)}
    , _key{std::move(key)}
    {}
    
    x509_crt _crt;
    x509_key _key;
  };
  
  certificate(std::shared_ptr<const model> self) : _self{std::move(self)} {}
  std::shared_ptr<const model> _self;
};

} // namespace impl
} // namespace jawtls

