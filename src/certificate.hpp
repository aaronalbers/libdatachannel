/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef RTC_CERTIFICATE_H
#define RTC_CERTIFICATE_H

#include "include.hpp"

#ifdef USE_OPENSSL
#include <openssl/x509.h>
#else
#include <gnutls/x509.h>
#endif

namespace rtc {

#ifdef USE_OPENSSL
using x509_crt_t = X509*;
using x509_privkey_t = EVP_PKEY*;
#else
using x509_crt_t = gnutls_x509_crt_t;
using x509_privkey_t = gnutls_x509_privkey_t;
#endif

class Certificate {
public:
   Certificate(x509_crt_t crt, x509_privkey_t privkey);
	Certificate(string crt_pem, string key_pem);

	string fingerprint() const;
#ifndef USE_OPENSSL
   gnutls_certificate_credentials_t credentials() const;
#endif

private:
#ifndef USE_OPENSSL
	std::shared_ptr<gnutls_certificate_credentials_t> mCredentials;
#endif
	string mFingerprint;
};

string make_fingerprint(x509_crt_t crt);
std::shared_ptr<Certificate> make_certificate(const string &commonName);

} // namespace rtc

#endif
