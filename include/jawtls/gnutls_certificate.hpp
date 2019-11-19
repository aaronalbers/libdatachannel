#pragma once

#include <memory>
#include <string>
#include <sstream>
#include <iomanip>

#include <gnutls/x509.h>
#include <gnutls/crypto.h>

namespace jawtls {
namespace impl {

static void check_result_and_throw(int result, const std::string& message) {
  if (result == GNUTLS_E_SUCCESS) return;
  throw std::runtime_error(message + ": " + gnutls_strerror(result));
}

static gnutls_x509_crt_t* create_crt() {
  auto crt = new gnutls_x509_crt_t;
  check_result_and_throw(gnutls_x509_crt_init(crt), "gnutls_x509_crt_init");
  return crt;
}

static void delete_crt(gnutls_x509_crt_t* crt) {
  gnutls_x509_crt_deinit(*crt);
  delete crt;
}

static gnutls_x509_privkey_t* create_privkey() {
  auto privkey = new gnutls_x509_privkey_t;
  check_result_and_throw(gnutls_x509_privkey_init(privkey), "gnutls_x509_privkey_init");
  return privkey;
}

static void delete_privkey(gnutls_x509_privkey_t* privkey) {
  gnutls_x509_privkey_deinit(*privkey);
  delete privkey;
}

using x509_crt = std::unique_ptr<gnutls_x509_crt_t, decltype(&delete_crt)>;
using x509_key = std::unique_ptr<gnutls_x509_privkey_t, decltype(&delete_privkey)>;

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
    x509_crt crt{create_crt(), delete_crt};
    x509_key privkey{create_privkey(), delete_privkey};

    const unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_HIGH);
    check_result_and_throw(gnutls_x509_privkey_generate(*privkey, GNUTLS_PK_RSA, bits, 0), "gnutls_x509_privkey_generate");

    using namespace std::chrono;
    auto now = time_point_cast<seconds>(system_clock::now());
    check_result_and_throw(gnutls_x509_crt_set_activation_time(*crt, (now - hours(1)).time_since_epoch().count()), "gnutls_x509_crt_set_activation_time");
    check_result_and_throw(gnutls_x509_crt_set_expiration_time(*crt, (now + hours(24 * 365)).time_since_epoch().count()), "gnutls_x509_crt_set_expiration_time");
    check_result_and_throw(gnutls_x509_crt_set_version(*crt, 1), "gnutls_x509_crt_set_version");
    check_result_and_throw(gnutls_x509_crt_set_key(*crt, *privkey), "gnutls_x509_crt_set_key");
    check_result_and_throw(gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME, 0, common_name.data(), common_name.size()), "gnutls_x509_crt_set_dn_by_oid");

    constexpr const size_t serialSize = 16;
    char serial[serialSize];
    check_result_and_throw(gnutls_rnd(GNUTLS_RND_NONCE, serial, serialSize), "gnutls_rnd");
    check_result_and_throw(gnutls_x509_crt_set_serial(*crt, serial, serialSize), "gnutls_x509_crt_set_serial");

    check_result_and_throw(gnutls_x509_crt_sign2(*crt, *crt, *privkey, GNUTLS_DIG_SHA256, 0), "gnutls_x509_crt_sign2");
    
    return std::make_shared<const model>(std::move(crt), std::move(privkey));
  }
  static fingerprint make_fingerprint(gnutls_x509_crt_t* crt) {
    constexpr const size_t size = 32;
    unsigned char buffer[size];
    size_t len = size;
    check_result_and_throw(gnutls_x509_crt_get_fingerprint(*crt, GNUTLS_DIG_SHA256, buffer, &len), "gnutls_x509_crt_get_fingerprint");

    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
      if (i) oss << std::setw(1) << ':';
      oss << std::setw(2) << unsigned(buffer[i]);
    }
    return oss.str();
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

} // namepsace impl
} // namespace jawtls

