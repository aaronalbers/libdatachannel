#pragma once

#include "config.hpp"
#include JAW_SELECT(certificate.hpp)

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace jawtls {

class session; // Forward Declare

class certificate final {
  friend class impl::certificate;
  friend class session;
  friend bool operator==(const certificate& lhs, const certificate& rhs) { return lhs._self == rhs._self; }
public:
  using fingerprint = impl::certificate::fingerprint;
  static certificate make_self_signed(const std::string& common_name) {
    static std::unordered_map<std::string, impl::certificate> cache;
    static std::mutex cache_mutex;

    std::lock_guard<std::mutex> scope_lock{cache_mutex};
    const auto find_it = cache.find(common_name);
    if (find_it != std::end(cache)) return find_it->second;
    
    return cache.emplace(std::make_pair(common_name, impl::certificate::make_self_signed(common_name))).first->second;
  }
  static fingerprint make_fingerprint(const certificate& cert) {
    static std::unordered_map<impl::certificate, fingerprint, impl::certificate::hasher> cache;
    static std::mutex cache_mutex;

    std::lock_guard<std::mutex> scope_lock{cache_mutex};
    const auto find_it = cache.find(cert._self);
    if (find_it != std::end(cache)) return find_it->second;
    
    return cache.emplace(std::make_pair(cert._self, impl::certificate::make_fingerprint(cert._self))).first->second;
  }
private:
  certificate(impl::certificate self) : _self{std::move(self)} {}
  impl::certificate _self;
};

} // namespace jawtls
