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

#include "dtlstransport.hpp"
#include "icetransport.hpp"

#include <cassert>
#include <cstring>
#include <exception>
#include <iostream>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#else
#include <gnutls/dtls.h>
#endif

using std::shared_ptr;
using std::string;

namespace {
#ifdef USE_OPENSSL
#else
static bool check_gnutls(int ret, const string &message = "GnuTLS error") {
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret))
			return false;
		throw std::runtime_error(message + ": " + gnutls_strerror(ret));
	}
	return true;
}
#endif

} // namespace

namespace rtc {

using std::shared_ptr;

DtlsTransport::DtlsTransport(shared_ptr<IceTransport> lower, shared_ptr<Certificate> certificate,
                             verifier_callback verifierCallback,
                             state_callback stateChangeCallback)
    : Transport(lower), mCertificate(certificate), mState(State::Disconnected),
      mVerifierCallback(std::move(verifierCallback)),
      mStateChangeCallback(std::move(stateChangeCallback)) {
#ifdef USE_OPENSSL
#else
	gnutls_certificate_set_verify_function(mCertificate->credentials(), CertificateCallback);

	bool active = lower->role() == Description::Role::Active;
	unsigned int flags = GNUTLS_DATAGRAM | (active ? GNUTLS_CLIENT : GNUTLS_SERVER);
	check_gnutls(gnutls_init(&mSession, flags));

	const char *priorities = "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128";
	const char *err_pos = NULL;
	check_gnutls(gnutls_priority_set_direct(mSession, priorities, &err_pos),
	             "Unable to set TLS priorities");

	gnutls_session_set_ptr(mSession, this);
	gnutls_transport_set_ptr(mSession, this);
	gnutls_transport_set_push_function(mSession, WriteCallback);
	gnutls_transport_set_pull_function(mSession, ReadCallback);
	gnutls_transport_set_pull_timeout_function(mSession, TimeoutCallback);

	check_gnutls(
	    gnutls_credentials_set(mSession, GNUTLS_CRD_CERTIFICATE, mCertificate->credentials()));
#endif

	mRecvThread = std::thread(&DtlsTransport::runRecvLoop, this);
}

DtlsTransport::~DtlsTransport() {
	mMessageQueue.stop();
	if (mRecvThread.joinable())
		mRecvThread.join();

#ifdef USE_OPENSSL
#else
	gnutls_bye(mSession, GNUTLS_SHUT_RDWR);
	gnutls_deinit(mSession);
#endif
}

DtlsTransport::State DtlsTransport::state() const { return mState; }

bool DtlsTransport::send(message_ptr message) {
	if (!message)
		return false;
  
  std::cout << "message outgoing" << std::endl;
  
   mMessageQueue.push({message_type::Outgoing, message});
   
   return true;
#if 0
#ifdef USE_OPENSSL
  // SSL_write()
  // BIO_read()
#else
	while (true) {
		ssize_t ret = gnutls_record_send(mSession, message->data(), message->size());
		if (check_gnutls(ret)) {
			return ret > 0;
		}
	}
#endif
#endif
}

void DtlsTransport::incoming(message_ptr message) { mMessageQueue.push({message_type::Incoming, message}); }

void DtlsTransport::changeState(State state) {
	mState = state;
	mStateChangeCallback(state);
}

void DtlsTransport::runRecvLoop() {
	try {
		changeState(State::Connecting);

#ifdef USE_OPENSSL
      // SSL_do_handshake()
#else
		while (!check_gnutls(gnutls_handshake(mSession), "TLS handshake failed"));
#endif
	} catch (const std::exception &e) {
		std::cerr << "DTLS handshake: " << e.what() << std::endl;
		changeState(State::Failed);
		return;
	}

	try {
		changeState(State::Connected);

		const size_t bufferSize = 2048;
		char buffer[bufferSize];

		while (true) {
        auto next = mMessageQueue.pop();
        if (!next) break;
        
        auto message_pair = *next;
        auto message = message_pair.second;
#ifdef USE_OPENSSL
         // BIO_write()
         // SSL_read()
#else
         if (message_pair.first == message_type::Incoming) {
            mIncomingMessage = message;
            ssize_t ret = gnutls_record_recv(mSession, buffer, bufferSize);
            if (check_gnutls(ret)) {
               if (ret == 0) {
                  // Closed
                  break;
               }
               auto *b = reinterpret_cast<byte *>(buffer);
               recv(make_message(b, b + ret));
            }
         } else if (message_pair.first == message_type::Outgoing) {
            while (true) {
               ssize_t ret = gnutls_record_send(mSession, message->data(), message->size());
               if (check_gnutls(ret)) break;
            }
         }
#endif
		}

	} catch (const std::exception &e) {
		std::cerr << "DTLS recv: " << e.what() << std::endl;
	}

	changeState(State::Disconnected);
	recv(nullptr);
}

#ifdef USE_OPENSSL
static int DtlsTransport_index = SSL_get_ex_new_index(0, (void*)("DtlsTransport index"), NULL, NULL, NULL);
int DtlsTransport::CertificateCallback(int ok, X509_STORE_CTX* ctx) {
   SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
   DtlsTransport *t = static_cast<DtlsTransport*>(SSL_get_ex_data(ssl, DtlsTransport_index));

   string fingerprint = make_fingerprint(X509_STORE_CTX_get_current_cert(ctx));

   bool success = ok && t->mVerifierCallback(fingerprint);
   return success ? 1 : 0;
}
#else
int DtlsTransport::CertificateCallback(gnutls_session_t session) {
	DtlsTransport *t = static_cast<DtlsTransport *>(gnutls_session_get_ptr(session));

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	unsigned int count = 0;
	const gnutls_datum_t *array = gnutls_certificate_get_peers(session, &count);
	if (!array || count == 0) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_x509_crt_t crt;
	check_gnutls(gnutls_x509_crt_init(&crt));
	int ret = gnutls_x509_crt_import(crt, &array[0], GNUTLS_X509_FMT_DER);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(crt);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	string fingerprint = make_fingerprint(crt);
	gnutls_x509_crt_deinit(crt);

	bool success = t->mVerifierCallback(fingerprint);
	return success ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;
}

ssize_t DtlsTransport::WriteCallback(gnutls_transport_ptr_t ptr, const void *data, size_t len) {
	DtlsTransport *t = static_cast<DtlsTransport *>(ptr);
	if (len > 0) {
		auto b = reinterpret_cast<const byte *>(data);
		t->outgoing(make_message(b, b + len));
	}
	gnutls_transport_set_errno(t->mSession, 0);
	return ssize_t(len);
}

ssize_t DtlsTransport::ReadCallback(gnutls_transport_ptr_t ptr, void *data, size_t maxlen) {
	DtlsTransport *t = static_cast<DtlsTransport *>(ptr);
	auto message = t->mIncomingMessage;
	if (!message) {
		// Closed
		gnutls_transport_set_errno(t->mSession, 0);
		return 0;
	}

	ssize_t len = std::min(maxlen, message->size());
	std::memcpy(data, message->data(), len);
	gnutls_transport_set_errno(t->mSession, 0);
	return len;
}

int DtlsTransport::TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int ms) {
	return 1; // So ReadCallback is called
}
#endif

} // namespace rtc
