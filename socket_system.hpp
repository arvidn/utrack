/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2013-2014 Arvid Norberg

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


#ifndef SOCKET_SYSTEM_HPP
#define SOCKET_SYSTEM_HPP

#include <array>
#include <cassert>

#ifndef _WIN32
#include <unistd.h> // for close
#include <poll.h> // for poll
#else
#include <winsock2.h>
#endif

#include "utils.hpp" // for address_eth
#include "config.hpp"

struct packet_buffer;

struct packet_socket
{
	friend struct packet_buffer;

	packet_socket(int listen_port, bool receive = false);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(packet_buffer& packets);

	void local_endpoint(sockaddr_in* addr);

	void add_arp_entry(sockaddr_in const* addr, address_eth const& mac) {}


	// receive at least one packet on the socket. No more than num (defaults
	// to 1000). For each received packet, callback is called with the following
	// arguments: (sockaddr_in* from, uint8_t* buffer, int len)
	// the buffer is valid until the callback returns
	// returns -1 on error
	template <class F>
	int receive(F callback, int num = 1000)
	{
		if (num == 0) return 0;

		sockaddr_in from;
		socklen_t fromlen = sizeof(from);

		// if there's no data available, try a few times in a row right away.
		// if there's still no data after that, go to sleep waiting for more
		int spincount = receive_spin_count;

		std::array<uint64_t, 1500/8> buf;

		// this loop is primarily here to be able to restart
		// in the event of EINTR and also in the case of no data
		// being available immediately (in which case we block in poll)
		while (true)
		{
			fromlen = sizeof(from);
			int size = recvfrom(m_socket, (char*)buf.data(), buf.size()*8, 0
				, (sockaddr*)&from, &fromlen);
			if (size == -1)
			{
#ifdef _WIN32
				int err = WSAGetLastError();
#else
				int err = errno;
#endif
				if (err == EINTR) continue;
#ifdef _WIN32
				if (err == WSAEWOULDBLOCK)
#else
					if (err == EAGAIN || errno == EWOULDBLOCK)
#endif
					{
						--spincount;
						if (spincount > 0) continue;
						// the first read came back empty, wait for new data
						// on the socket and try again
						pollfd e;
						e.fd = m_socket;
						e.events = POLLIN;
						e.revents = 0;

						spincount = receive_spin_count;

#ifdef _WIN32
						int r = WSAPoll(&e, 1, 2000);
#else
						int r = poll(&e, 1, 2000);
#endif
						if (r == -1)
						{
							if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
								continue;
							fprintf(stderr, "poll failed (%d): %s\n", err, strerror(err));
							return -1;
						}

						if (r == 0)
						{
							// no events, see if the socket was closed
							if (m_socket == -1) return -1;
							continue;
						}

						if ((e.revents & POLLHUP) || (e.revents & POLLERR))
						{
							fprintf(stderr, "poll returned socket failure (%d): %s\n"
								, err, strerror(err));
							return -1;
						}
						continue;
					}
				fprintf(stderr, "recvfrom failed (%d): %s\n", err, strerror(err));
				return -1;
			}

			callback(&from, (uint8_t const*)buf.data(), size);
			break;
		}

		return 1;
	}

private:
	int m_socket;
	bool m_receive;
};

struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s)
		: m_socket(s.m_socket)
	{}

	bool is_full(int buf_size) const { return false; }

	bool append(iovec const* v, int num, sockaddr_in const* to);

private:
	int m_socket;
};

#endif // SOCKET_SYSTEM_HPP

