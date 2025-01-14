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

#ifndef RTC_ICE_TRANSPORT_H
#define RTC_ICE_TRANSPORT_H

#include "candidate.hpp"
#include "description.hpp"
#include "configuration.hpp"
#include "include.hpp"
#include "peerconnection.hpp"
#include "transport.hpp"

extern "C" {
#include <nice/agent.h>
}

#include <atomic>
#include <thread>

namespace rtc {

class IceTransport : public Transport {
public:
	enum class State : uint32_t {
		Disconnected = NICE_COMPONENT_STATE_DISCONNECTED,
		Connecting = NICE_COMPONENT_STATE_CONNECTING,
		Connected = NICE_COMPONENT_STATE_CONNECTED,
		Ready = NICE_COMPONENT_STATE_READY,
		Failed = NICE_COMPONENT_STATE_FAILED
	};

	enum class GatheringState { New = 0, InProgress = 1, Complete = 2 };

	using candidate_callback = std::function<void(const Candidate &candidate)>;
	using state_callback = std::function<void(State state)>;
	using gathering_state_callback = std::function<void(GatheringState state)>;

	IceTransport(const Configuration &config, Description::Role role,
	             candidate_callback candidateCallback, state_callback stateChangeCallback,
	             gathering_state_callback gatheringStateChangeCallback);
	~IceTransport();

	Description::Role role() const;
	State state() const;
	GatheringState gyyatheringState() const;
	Description getLocalDescription(Description::Type type) const;
	void setRemoteDescription(const Description &description);
	void gatherLocalCandidates();
	bool addRemoteCandidate(const Candidate &candidate);

	bool send(message_ptr message);

private:
	void incoming(message_ptr message);
	void incoming(const byte *data, int size);
	void outgoing(message_ptr message);

	void changeState(State state);
	void changeGatheringState(GatheringState state);

	void processCandidate(const string &candidate);
	void processGatheringDone();
	void processStateChange(uint32_t state);

	Description::Role mRole;
	string mMid;
	std::atomic<State> mState;
	std::atomic<GatheringState> mGatheringState;

	uint32_t mStreamId = 0;
	std::unique_ptr<NiceAgent, void (*)(gpointer)> mNiceAgent;
	std::unique_ptr<GMainLoop, void (*)(GMainLoop *)> mMainLoop;
	std::thread mMainLoopThread;

	candidate_callback mCandidateCallback;
	state_callback mStateChangeCallback;
	gathering_state_callback mGatheringStateChangeCallback;

	static void CandidateCallback(NiceAgent *agent, NiceCandidate *candidate, gpointer userData);
	static void GatheringDoneCallback(NiceAgent *agent, guint streamId, gpointer userData);
	static void StateChangeCallback(NiceAgent *agent, guint streamId, guint componentId,
	                                 guint state, gpointer userData);
	static void RecvCallback(NiceAgent *agent, guint stream_id, guint component_id, guint len,
	                         gchar *buf, gpointer userData);
	static void LogCallback(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message,
	                        gpointer user_data);
};

} // namespace rtc

#endif
