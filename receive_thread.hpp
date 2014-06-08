/*
Copyright (C) 2010-201$  Arvid Norberg

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

#ifndef _RECEIVE_THREAD_HPP_
#define _RECEIVE_THREAD_HPP_

#include <thread>
#include <atomic>
#include <cstdint>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>

#include "socket.hpp"
#include "announce_thread.hpp" // for announce_msg

struct announce_thread;

// this is a thread that reads packets off the UDP socket and forwards it to
// to appropriate announce_thread (if it's an announce)
struct receive_thread
{
#ifdef USE_PCAP
	receive_thread(packet_socket& s, std::vector<announce_thread*> const& at);
#else
	receive_thread(std::vector<announce_thread*> const& at);
#endif
	~receive_thread();

	// allow move
	receive_thread(receive_thread&&) = default;
	receive_thread& operator=(receive_thread&&) = default;

	// disallow copy
	receive_thread(receive_thread const&) = delete;
	receive_thread& operator=(receive_thread const&) = delete;

	void close();

	std::thread::native_handle_type native_handle() { return m_thread.native_handle(); }

	void thread_fun();

	// this thread receives incoming announces, parses them and posts
	// the announce to the correct announce thread, that then takes over
	// and is responsible for responding
	void incoming_packet(char const* buf, int size, sockaddr_in const* from
		, socklen_t fromlen, packet_buffer& send_buffer
		, std::vector<announce_msg>* announce_buf);

private:

#ifdef USE_PCAP
	packet_socket& m_sock;
#else
	packet_socket m_sock;
	packet_socket m_send_sock;
#endif
	std::vector<announce_thread*> const& m_announce_threads;

	std::thread m_thread;
};

#endif


