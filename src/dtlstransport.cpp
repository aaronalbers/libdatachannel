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

using std::shared_ptr;
using std::string;

namespace rtc {

using std::shared_ptr;

DtlsTransport::DtlsTransport(shared_ptr<IceTransport> lower, Certificate certificate,
                             verifier_callback verifierCallback,
                             state_callback stateChangeCallback)
: Transport{lower}
, mSession{Session::make(std::bind(&DtlsTransport::queueSerialTask, this, std::placeholders::_1),
                         lower->role() == Description::Role::Active ? Session::role::client : Session::role::server,
                         std::move(certificate),
                         std::bind(&DtlsTransport::sendEncrypted, this, std::placeholders::_1),
                         std::bind(&DtlsTransport::onUnencrypted, this, std::placeholders::_1),
                         std::move(verifierCallback))}
, mState{State::Disconnected}
, mStateChangeCallback{std::move(stateChangeCallback)} {
	mTaskThread = std::thread(&DtlsTransport::runTaskLoop, this);
}

DtlsTransport::~DtlsTransport() {
	mTaskQueue.stop();
  mTaskThread.join();

	//gnutls_bye(mSession, GNUTLS_SHUT_RDWR);
	//gnutls_deinit(mSession);
}

void DtlsTransport::queueSerialTask(std::function<void()> task) {
  mTaskQueue.push(std::move(task));
}

void DtlsTransport::onUnencrypted(Session::unencrypted_payload payload) {
  auto *b = reinterpret_cast<byte *>(payload.data.data());
  recv(make_message(b, b + payload.data.size()));
}
void DtlsTransport::sendEncrypted(Session::encrypted_payload payload) {
  auto b = reinterpret_cast<const byte *>(payload.data.data());
  outgoing(make_message(b, b + payload.data.size()));
}

DtlsTransport::State DtlsTransport::state() const { return mState; }

bool DtlsTransport::send(message_ptr message) {
	if (!message)
		return false;
  auto b = reinterpret_cast<const char *>(message->data());
	mSession(Session::unencrypted_payload{std::string{b, message->size()}});
  return true;
}

void DtlsTransport::incoming(message_ptr message) {
  auto b = reinterpret_cast<const char *>(message->data());
  mSession(Session::encrypted_payload{std::string{b, message->size()}});
}

void DtlsTransport::changeState(State state) {
	mState = state;
	mStateChangeCallback(state);
}

void DtlsTransport::runTaskLoop() {
  changeState(State::Connecting);
  //changeState(State::Failed);
  changeState(State::Connected);

	while (true) {
    auto task = mTaskQueue.pop();
    if (!task) break;
    (*task)();
  }

	changeState(State::Disconnected);
	//recv(nullptr);
}

} // namespace rtc
