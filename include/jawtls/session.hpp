#pragma once

#include "config.hpp"
#include JAW_SELECT(session.hpp)

#include "certificate.hpp" // TODO(albers): Forward declare and create fingerprint.hpp

namespace jawtls {

class session final {
  friend class impl::session;
  friend bool operator==(const session& lhs, const session& rhs) { return lhs._self == rhs._self; }
public:
  using encrypted_payload = impl::session::encrypted_payload;
  using unencrypted_payload = impl::session::unencrypted_payload;
  using fingerprint = certificate::fingerprint;
  using encrypted_data_out_func = impl::session::encrypted_data_out_func;
  using unencrypted_data_out_func = impl::session::unencrypted_data_out_func;
  using verify_fingerprint_func = impl::session::verify_fingerprint_func;
  using role = impl::session::role;
  using executor = impl::session::executor;
  
  static session make(executor e,
                      role type,
                      certificate cert,
                      encrypted_data_out_func encrypted_out,
                      unencrypted_data_out_func unencrypted_out,
                      verify_fingerprint_func verify_func = nullptr) {
    if (!encrypted_out) throw std::runtime_error("encrypted_out not defined");
    if (!unencrypted_out) throw std::runtime_error("unencrypted_out not defined");
    return impl::session::make(std::move(e),
                               type,
                               std::move(cert._self),
                               std::move(encrypted_out),
                               std::move(unencrypted_out),
                               std::move(verify_func));
  }
  
  void operator()(encrypted_payload payload) { _self(std::move(payload)); }
  void operator()(unencrypted_payload payload) { _self(std::move(payload)); }
  
private:
  session(impl::session self) : _self{std::move(self)} {}
  impl::session _self;
};

} // namespace jawtls
