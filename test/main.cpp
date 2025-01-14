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

#include "rtc/rtc.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

using namespace rtc;
using namespace std;

int main(int argc, char **argv) {
	rtc::Configuration config;
	// config.iceServers.emplace_back("stun.l.google.com:19302");

	auto pc1 = std::make_shared<PeerConnection>(config);
	auto pc2 = std::make_shared<PeerConnection>(config);

	pc1->onLocalDescription([pc2](const Description &sdp) {
		cout << "Description 1: " << sdp << endl;
		pc2->setRemoteDescription(sdp);
	});

	pc1->onLocalCandidate([pc2](const Candidate &candidate) {
		cout << "Candidate 1: " << candidate << endl;
		pc2->addRemoteCandidate(candidate);
	});

	pc1->onStateChange([](PeerConnection::State state) { cout << "State 1: " << state << endl; });
	pc1->onGatheringStateChange([](PeerConnection::GatheringState state) {
		cout << "Gathering state 1: " << state << endl;
	});

	pc2->onLocalDescription([pc1](const Description &sdp) {
		cout << "Description 2: " << sdp << endl;
		pc1->setRemoteDescription(sdp);
	});

	pc2->onLocalCandidate([pc1](const Candidate &candidate) {
		cout << "Candidate 2: " << candidate << endl;
		pc1->addRemoteCandidate(candidate);
	});

	pc2->onStateChange([](PeerConnection::State state) { cout << "State 2: " << state << endl; });
	pc2->onGatheringStateChange([](PeerConnection::GatheringState state) {
		cout << "Gathering state 2: " << state << endl;
	});

	shared_ptr<DataChannel> dc2;
	pc2->onDataChannel([&dc2](shared_ptr<DataChannel> dc) {
		cout << "Got a DataChannel with label: " << dc->label() << endl;
		dc2 = dc;
		dc2->onMessage([](const variant<binary, string> &message) {
			if (holds_alternative<string>(message)) {
				cout << "Received 2: " << get<string>(message) << endl;
			}
		});
		dc2->send("Hello from 2");
	});

	auto dc1 = pc1->createDataChannel("test");
	dc1->onOpen([dc1]() {
		cout << "DataChannel open: " << dc1->label() << endl;
		dc1->send("Hello from 1");
	});
	dc1->onMessage([](const variant<binary, string> &message) {
		if (holds_alternative<string>(message)) {
			cout << "Received 1: " << get<string>(message) << endl;
		}
	});

	this_thread::sleep_for(10s);
}

