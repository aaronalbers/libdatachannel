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

#include "session.hpp"
#include "include.hpp"
#include "peerconnection.hpp"
#include "queue.hpp"
#include "transport.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

namespace rtc {

class IceTransport;

class DtlsTransport : public Transport {
public:
	enum class State { Disconnected, Connecting, Connected, Failed };

	using verifier_callback = std::function<bool(const std::string &fingerprint)>;
	using state_callback = std::function<void(State state)>;
  using Certificate = jawtls::certificate;
  using Session = jawtls::session;

	DtlsTransport(std::shared_ptr<IceTransport> lower, Certificate certificate,
	              verifier_callback verifierCallback, state_callback stateChangeCallback);
	~DtlsTransport();

	State state() const;

	bool send(message_ptr message);

private:
  using Task = std::function<void()>;
	void incoming(message_ptr message);
	void changeState(State state);
  void queueSerialTask(Task task);
	void runTaskLoop();

  Queue<Task> mTaskQueue;
	Session mSession;
	std::atomic<State> mState;
	std::thread mTaskThread;
  
	state_callback mStateChangeCallback;
  void onUnencrypted(Session::unencrypted_payload payload);
  void sendEncrypted(Session::encrypted_payload payload);
};

} // namespace rtc

#endif

