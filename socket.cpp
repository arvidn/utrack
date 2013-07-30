/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2013  Arvid Norberg

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

#include "socket.hpp"
#include <stdio.h> // for stderr
#include <errno.h> // for errno
#include <string.h> // for strerror
#include <stdlib.h> // for exit
#include <unistd.h> // for close

#include <atomic>
#include <assert.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

extern std::atomic<uint32_t> bytes_out;

packet_socket::packet_socket(bool receive)
	: m_socket(-1)
	, m_receive(receive)
{
	m_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (m_socket < 0)
	{
		fprintf(stderr, "failed to open socket (%d): %s\n"
			, errno, strerror(errno));
		exit(1);
	}

	extern int socket_buffer_size;
	int opt = socket_buffer_size;
	int r = setsockopt(m_socket, SOL_SOCKET, m_receive ? SO_RCVBUF : SO_SNDBUF, &opt, sizeof(opt));
	if (r == -1)
	{
		fprintf(stderr, "failed to set socket %s buffer size (%d): %s\n"
			, m_receive ? "receive" : "send", errno, strerror(errno));
	}

	int one = 1;
	if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEADDR on socket (%d): %s\n"
			, errno, strerror(errno));
	}

#ifdef SO_REUSEPORT
	if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEPORT on socket (%d): %s\n"
			, errno, strerror(errno));
	}
#endif

	extern int listen_port;

	if (m_receive)
	{
		sockaddr_in bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_addr.s_addr = INADDR_ANY;
		bind_addr.sin_port = htons(listen_port);
		r = bind(m_socket, (sockaddr*)&bind_addr, sizeof(bind_addr));
		if (r < 0)
		{
			fprintf(stderr, "failed to bind socket to port %d (%d): %s\n"
				, listen_port, errno, strerror(errno));
			exit(1);
		}
	}
}

packet_socket::~packet_socket()
{
	if (m_socket != -1) ::close(m_socket);
}

void packet_socket::close()
{
	if (m_socket != -1) ::close(m_socket);
	m_socket = -1;
}

packet_socket::packet_socket(packet_socket&& s)
	: m_socket(s.m_socket)
{
	s.m_socket = -1;
}

// send a packet and retry on EINTR
bool packet_socket::send(iovec const* v, int num, sockaddr const* to, socklen_t tolen)
{
	msghdr msg;
	msg.msg_name = (void*)to;
	msg.msg_namelen = tolen;
	msg.msg_iov = (iovec*)v;
	msg.msg_iovlen = num;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	// silly loop just to deal with the potential EINTR
	do
	{
		int r = sendmsg(m_socket, &msg, MSG_NOSIGNAL);
		if (r == -1)
		{
			if (errno == EINTR) continue;
			fprintf(stderr, "sendmsg failed (%d): %s\n", errno, strerror(errno));
			return 1;
		}
		bytes_out += r;
	} while (false);
	return 0;
}

int packet_socket::receive(incoming_packet_t* in_packets, int num)
{
	assert(m_receive);
	if (num == 0) return 0;

	sockaddr_in from;
	socklen_t fromlen = sizeof(from);

	// TODO;: it could be faster to drain the UDP socket in a loop here, since the kernel code path is hot in the cache
	int size;
	do
	{
		fromlen = sizeof(from);
		size = recvfrom(m_socket, (char*)m_buffer, sizeof(m_buffer), 0
			, (sockaddr*)&from, &fromlen);
		if (size == -1)
		{
			if (errno == EINTR) continue;
			fprintf(stderr, "recvfrom failed (%d): %s\n", errno, strerror(errno));
			return -1;
		}
	} while (false);

	memcpy(&in_packets[0].from, &from, sizeof(from));
	in_packets[0].fromlen = fromlen;
	in_packets[0].buffer = (char*)m_buffer;
	in_packets[0].buflen = size;
	return 1;
}

