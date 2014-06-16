/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2010-2014 Arvid Norberg

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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

#include "messages.hpp"
#include "endian.hpp"
#include "socket.hpp"

std::atomic<uint32_t> bytes_out(ATOMIC_VAR_INIT(0));
bool m_quit = false;

sha1_hash random_hash()
{
	sha1_hash ret;
	for (int i = 0; i < 5; ++i)
	{
		ret.val[i] = (rand() << 16) ^ rand();
	}
	return ret;
}

sha1_hash get_info_hash(int idx)
{
	sha1_hash ret;
	for (int i = 0; i < 5; ++i)
	{
		ret.val[i] = idx & 0xff;
	}
	return ret;
}

void send_connect(sockaddr_in const* to, packet_buffer& buf)
{
	static int idx = 0;

	// only announce 2^24 times. at 100k requests / second that's
	// still almost 3 minutes of runtime
	if (idx > 0xffffff) return;

	idx = (idx + 1) & 0xffffff;

	udp_announce_message req;
	req.connection_id = be64toh(0x41727101980LL);
	req.action = htonl(action_connect);
	req.transaction_id = htonl(idx);

	sockaddr_in from;
	from.sin_family = AF_INET;
	from.sin_port = htons(1024 + idx);
	from.sin_len = sizeof(sockaddr_in);
	from.sin_addr.s_addr = htonl(0x7f000000 + idx);

	iovec b = { &req, 16 };
	buf.append_impl(&b, 1, to, &from);
}

void send_announce(int idx, uint64_t connection_id, sockaddr_in const* to
	, packet_buffer& buf)
{
	udp_announce_message req;
	req.action = htonl(action_announce);
	req.connection_id = connection_id;
	req.transaction_id = htonl((1 << 24) | idx);
	req.hash = get_info_hash(idx);
	req.peer_id = random_hash();
	req.event = htonl(event_started);
	req.ip = 0;
	req.key = htonl(idx);
	req.num_want = htonl(200);
	req.port = htons(1024 + idx);
	req.extensions = 0;

	sockaddr_in from;
	from.sin_family = AF_INET;
	from.sin_port = htons(1024 + idx);
	from.sin_len = sizeof(sockaddr_in);
	from.sin_addr.s_addr = htonl(0x7f000000 + idx);

	iovec b = { &req, sizeof(req) };
	buf.append_impl(&b, 1, to, &from);
}

void incoming_packet(char const* buf, int size
	, sockaddr_in const* from, packet_buffer& send_buffer)
{
	udp_announce_response const* resp = (udp_announce_response const*)buf;

	if (size < sizeof(udp_connect_response))
	{
		fprintf(stderr, "incoming packet too small (%d)\n", size);
		return;
	}

	switch (ntohl(resp->action))
	{
		case action_announce:
		{
			int idx = ntohl(resp->transaction_id);
			if ((idx >> 24) != 1)
			{
				fprintf(stderr, "invalid transaction id for announce response\n");
				return;
			}
			idx &= 0xffffff;
			static int num_responses = 0;
			++num_responses;
			if (num_responses == 0xffffff) m_quit = true;
			break;
		}
		case action_connect:
		{
			udp_connect_response const* resp = (udp_connect_response const*)buf;
			int idx = ntohl(resp->transaction_id);
			if ((idx >> 24) != 0)
			{
				fprintf(stderr, "invalid transaction id for connect response\n");
				return;
			}

			send_announce(idx, resp->connection_id, from, send_buffer);
			send_connect(from, send_buffer);
			break;
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		fprintf(stderr, "usage: ./udp_test device address port\n");
		return EXIT_FAILURE;
	}

	sockaddr_in to;
	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	int r = inet_pton(AF_INET, argv[2], &to.sin_addr);
	if (r < 0)
	{
		fprintf(stderr, "invalid target address \"%s\" (%d): %s\n", argv[1]
			, errno, strerror(errno));
		return EXIT_FAILURE;
	}
	to.sin_port = htons(atoi(argv[3]));

	packet_socket sock(argv[1], 0);
	packet_buffer send_buffer(sock);

	for (int k = 0; k < 50; ++k)
	{
		for (int i = 0; i < 1000; ++i)
			send_connect(&to, send_buffer);
		sock.send(send_buffer);
	}

	incoming_packet_t pkts[1024];
	while (!m_quit)
	{
		int recvd = sock.receive(pkts, sizeof(pkts)/sizeof(pkts[0]));
		if (recvd <= 0) break;
		for (int i = 0; i < recvd; ++i)
		{
			incoming_packet(pkts[i].buffer, pkts[i].buflen
				, (sockaddr_in*)&pkts[i].from, send_buffer);
		}

		sock.send(send_buffer);
	}
	return EXIT_SUCCESS;
}

