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

#ifndef RTC_DTLS_TRANSPORT_H
#define RTC_DTLS_TRANSPORT_H

#include "certificate.hpp"
#include "include.hpp"
#include "peerconnection.hpp"
#include "queue.hpp"
#include "transport.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <thread>
#include <utility>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
typedef struct {
  SSL_CTX* ctx; /* main ssl context */
  SSL* ssl; /* the SSL* which represents a "connection" */
  BIO* in_bio; /* we use memory read bios */
  BIO* out_bio; /* we use memory write bios */
} krx;
#else
#include <gnutls/gnutls.h>
#endif

namespace rtc {

class IceTransport;

class DtlsTransport : public Transport {
public:
	enum class State { Disconnected, Connecting, Connected, Failed };

	using verifier_callback = std::function<bool(const std::string &fingerprint)>;
	using state_callback = std::function<void(State state)>;

	DtlsTransport(std::shared_ptr<IceTransport> lower, std::shared_ptr<Certificate> certificate,
	              verifier_callback verifierCallback, state_callback stateChangeCallback);
	~DtlsTransport();

	State state() const;

	bool send(message_ptr message);

private:
	void incoming(message_ptr message);
	void changeState(State state);
	void runRecvLoop();

	const std::shared_ptr<Certificate> mCertificate;

#ifdef USE_OPENSSL
   krx mSession;
#else
	gnutls_session_t mSession;
   message_ptr mIncomingMessage;
#endif
   enum class message_type { Incoming, Outgoing };
	Queue<std::pair<message_type, message_ptr>> mMessageQueue;
	std::atomic<State> mState;
	std::thread mRecvThread;

	verifier_callback mVerifierCallback;
	state_callback mStateChangeCallback;

#ifdef USE_OPENSSL
   static int CertificateCallback(int ok, X509_STORE_CTX* ctx);
#else
	static int CertificateCallback(gnutls_session_t session);
	static ssize_t WriteCallback(gnutls_transport_ptr_t ptr, const void *data, size_t len);
	static ssize_t ReadCallback(gnutls_transport_ptr_t ptr, void *data, size_t maxlen);
	static int TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int ms);
 #endif
};

} // namespace rtc

#endif

