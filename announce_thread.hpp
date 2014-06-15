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
#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>

#include <thread>
#include <queue>
#include <unordered_map>
#include <array>
#include <vector>

struct announce_msg
{
	union
	{
		udp_announce_message announce;
		udp_scrape_message scrape;
	} bits;
	sockaddr_in from;
};

extern "C" int siphash(unsigned char *out, const unsigned char *in
	, unsigned long long inlen, const unsigned char *k);

std::array<uint8_t, 16> gen_random_key();

struct siphash_fun
{
	size_t operator()(sha1_hash const& h) const
	{
		// this is the secret key used in siphash to prevent hashcolision
		// attacks. It's initialized to random bytes on startup (or first use)
		static std::array<uint8_t, 16> hash_key = gen_random_key();

		std::uint64_t ret;
		siphash((std::uint8_t*)&ret, (std::uint8_t const*)h.val, sizeof(h.val)
			, hash_key.data());
		return ret;
	}
};

// this is a thread that handles the announce for a specific
// set of info-hashes, and then sends a response over its own
// UDP socket
struct announce_thread
{
#ifdef USE_PCAP
	announce_thread(packet_socket& s);
#else
	announce_thread();
#endif

	// allow move
	announce_thread(announce_thread&&) = default;
	announce_thread& operator=(announce_thread&&) = default;

	// disallow copy
	announce_thread(announce_thread const&) = delete;
	announce_thread& operator=(announce_thread const&) = delete;

	void thread_fun();
	void post_announces(std::vector<announce_msg> const& m);
	~announce_thread();

	std::thread::native_handle_type native_handle() { return m_thread.native_handle(); }

private:

	// job queue
	std::mutex m_mutex;
	std::condition_variable m_cond;
	// this is the queue new jobs are posted to
	std::vector<announce_msg> m_queue;

	// the swarm hash table. Each thread has its own hash table of swarms.
	// swarms are pinned to certain threads based on their info-hash
	typedef std::unordered_map<sha1_hash, swarm, siphash_fun> swarm_map_t;
	swarm_map_t m_swarms;

#ifdef USE_PCAP
	packet_socket& m_sock;
#else
	// socket used to send responses to
	packet_socket m_sock;
#endif

	bool m_quit;
	std::thread m_thread;
};

#endif

