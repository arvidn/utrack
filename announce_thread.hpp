/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2010-2013  Arvid Norberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ANNOUNCE_THREAD_HPP_
#define _ANNOUNCE_THREAD_HPP_

#include "messages.hpp"
#include "swarm.hpp"

#include <sys/socket.h>
#include <netinet/in.h>

#include <thread>
#include <queue>
#include <unordered_map>

struct announce_msg
{
	udp_announce_message m;
	sockaddr_in from;
	socklen_t fromlen;
};

// this is a thread that handles the announce for a specific
// set of info-hashes, and then sends a response over its own
// UDP socket
struct announce_thread
{
	announce_thread() : m_quit(false), m_thread( [=]() { thread_fun(); } ) {}

	announce_thread(announce_thread const&) = delete;
	announce_thread& operator=(announce_thread const&) = delete;

	void thread_fun();
	void post_announce(announce_msg const& m);
	~announce_thread();

private:

	// job queue
	std::mutex m_mutex;
	std::condition_variable m_cond;
	std::deque<announce_msg> m_queue;

	// the swarm hash table. Each thread has its own hash table of swarms.
	// swarms are pinned to certain threads based on their info-hash
	typedef std::unordered_map<sha1_hash, swarm, sha1_hash_fun> swarm_map_t;
	swarm_map_t m_swarms;

	bool m_quit;
	std::thread m_thread;
};

#endif

