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
#include <signal.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sys/sysctl.h>
#include <net/if.h>

#ifndef __linux__
#include <net/if_dl.h>
#include <net/if_types.h>
#endif

#else
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#include "messages.hpp"
#include "endian.hpp"
#include "socket.hpp"

std::atomic<uint32_t> bytes_out(ATOMIC_VAR_INIT(0));
std::atomic<uint32_t> dropped_bytes_out = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> connects = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> announces = ATOMIC_VAR_INIT(0);
std::atomic<bool> m_quit(ATOMIC_VAR_INIT(false));

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

void send_connect(sockaddr_in const* to, packet_buffer& buf, bool loopback)
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

	iovec b = { &req, 16 };

#if !defined USE_SYSTEM_SEND_SOCKET && defined USE_PCAP
	if (loopback)
	{
		sockaddr_in from;
		from.sin_family = AF_INET;
		from.sin_port = htons(1024 + idx);
#if !defined _WIN32 && !defined __linux__
		from.sin_len = sizeof(sockaddr_in);
#endif
		from.sin_addr.s_addr = htonl(0x7f000001 + idx);

		buf.append_impl(&b, 1, to, &from);
	}
	else
#endif // USE_PCAP
	{
		buf.append(&b, 1, to);
	}
}

void send_announce(int idx, uint64_t connection_id, sockaddr_in const* to
	, packet_buffer& buf, bool loopback)
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

	iovec b = { &req, sizeof(req) };

#if !defined USE_SYSTEM_SEND_SOCKET && defined USE_PCAP
	if (loopback)
	{
		sockaddr_in from;
		from.sin_family = AF_INET;
		from.sin_port = htons(1024 + idx);
#if !defined _WIN32 && !defined __linux__
		from.sin_len = sizeof(sockaddr_in);
#endif
		from.sin_addr.s_addr = htonl(0x7f000001 + idx);

		buf.append_impl(&b, 1, to, &from);
	}
	else
#endif // USE_PCAP
	{
		buf.append(&b, 1, to);
	}
}

void incoming_packet(uint8_t const* buf, int size
	, sockaddr_in const* from, packet_buffer& send_buffer, bool loopback)
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
			announces.fetch_add(1, std::memory_order_relaxed);
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

			connects.fetch_add(1, std::memory_order_relaxed);
			send_announce(idx, resp->connection_id, from, send_buffer, loopback);
			if ((idx & 0x1) == 0)
				send_announce(idx, resp->connection_id, from, send_buffer, loopback);

			send_connect(from, send_buffer, loopback);

			// every 4th connect response, send an additional connect, to
			// keep ramping up the conect rate indefinitely (until we bump
			// up against the capacity and packets are lost)
			send_connect(from, send_buffer, loopback);
			break;
		}
	}
}

packet_socket* g_sock = nullptr;

#ifdef _WIN32
BOOL WINAPI sigint(DWORD s)
#else
void sigint(int s)
#endif
{
	m_quit = true;
	if (g_sock) g_sock->close();
#ifdef _WIN32
	return TRUE;
#endif
}

#ifdef _WIN32
static struct wsa_init_t {
	wsa_init_t()
	{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
	}
} dummy_initializer;
#endif

int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		fprintf(stderr, "usage: ./udp_test device address port\n");
		return EXIT_FAILURE;
	}

	int r;
#ifndef _WIN32
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sigint;
	r = sigaction(SIGINT, &sa, 0);
	if (r == -1)
	{
		fprintf(stderr, "sigaction failed (%d): %s\n", errno, strerror(errno));
		return 1;
	}
	r = sigaction(SIGTERM, &sa, 0);
	if (r == -1)
	{
		fprintf(stderr, "sigaction failed (%d): %s\n", errno, strerror(errno));
		return 1;
	}
#else
	if (SetConsoleCtrlHandler(&sigint, TRUE) == FALSE)
	{
		std::error_code ec(GetLastError(), std::system_category());
		fprintf(stderr, "failed to register Ctrl-C handler: (%d) %s\n"
			, ec.value(), ec.message().c_str());
	}
#endif

	sockaddr_in to;
	memset(&to, 0, sizeof(to));
#if !defined _WIN32 && !defined __linux__
	to.sin_len = sizeof(to);
#endif
	to.sin_family = AF_INET;
	r = inet_pton(AF_INET, argv[2], &to.sin_addr);
	if (r < 0)
	{
		fprintf(stderr, "invalid target address \"%s\" (%d): %s\n", argv[1]
			, errno, strerror(errno));
		return EXIT_FAILURE;
	}
	to.sin_port = htons(atoi(argv[3]));

#if defined USE_SYSTEM_SEND_SOCKET || !defined USE_PCAP
	packet_socket sock(0);
#else

	address_eth mac;

	// we need to find out the MAC address of the destination computer
	// since we're sending raw ethernet frames. This works on OSX and BSD:

	std::error_code ec;
	std::vector<arp_entry> arp = arp_table(ec);
	if (ec)
	{
		fprintf(stderr, "failed to query ARP table: \"%s\"\n"
			, ec.message().c_str());
		exit(1);
	}

	auto i = std::find_if(arp.begin(), arp.end()
		, [=](arp_entry const& a){ return sockaddr_eq(&a.addr, (sockaddr const*)&to); });

	if (i == arp.end())
	{
		fprintf(stderr, "WARNING: no ARP entry found for \"%s\". please ping it\n"
			, argv[2]);
	}

	packet_socket sock(argv[1]);
	if (i != arp.end())
		sock.add_arp_entry(&to, i->hw_addr);
#endif // USE_SYSTEM_SEND_SOCKET
	packet_buffer send_buffer(sock);

	g_sock = &sock;

	typedef std::chrono::high_resolution_clock clock;
	using std::chrono::duration_cast;
	using std::chrono::milliseconds;
	using std::chrono::seconds;

	sockaddr_in ep;
	sock.local_endpoint(&ep);
	bool loopback = (ep.sin_addr.s_addr == htonl(0x7f000001));
	if (loopback) printf("loopback address\n");

	clock::time_point start = clock::now();

	for (int i = 0; i < 10000; ++i)
		send_connect(&to, send_buffer, loopback);
	sock.send(send_buffer);

	while (!m_quit.load())
	{
		int r = sock.receive(
			[&](sockaddr_in const* from, uint8_t const* buf, int len)
			{
				incoming_packet(buf, len, from, send_buffer, loopback);
			});

		sock.send(send_buffer);

		clock::time_point now = clock::now();
		if (now - start > seconds(5))
		{
			uint32_t last_connects = connects.exchange(0);
			uint32_t last_announces = announces.exchange(0);

			int ms = duration_cast<milliseconds>(now - start).count();

			printf("connects/s: %u announces/s: %u\n"
				, last_connects * 1000 / ms
				, last_announces * 1000 / ms);
			start = now;
		}
		if (r < 0) break;
	}

	clock::time_point end = clock::now();

	uint32_t last_connects = connects.exchange(0);
	uint32_t last_announces = announces.exchange(0);

	int ms = duration_cast<milliseconds>(end - start).count();

	printf("connects/s: %u announces/s: %u\n"
		, last_connects * 1000 / ms
		, last_announces * 1000 / ms);

	return EXIT_SUCCESS;
}

