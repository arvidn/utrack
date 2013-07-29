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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <thread>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <deque>
#include <cstdlib> // for rand()

#include "swarm.hpp"
#include "messages.hpp"
#include "endian.hpp"
#include "announce_thread.hpp"
#include "socket.hpp"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// if this is true, we allow peers to set which IP
// they will announce as. This is off by default since
// it allows for spoofing
bool allow_alternate_ip = false;

int interval = 1800;

int listen_port = 8080;

int socket_buffer_size = 5 * 1024 * 1024;

// set to true when we're shutting down
volatile bool quit = false;

// partial SHA-1 hash of the secret key, combined with
// source IP and port it forms the connection-id
// TODO: use something more efficient than SHA-1
SHA_CTX secret;

// stats counters
std::atomic<uint32_t> connects = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> announces = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> scrapes = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> errors = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> bytes_out = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> bytes_in = ATOMIC_VAR_INIT(0);

// the number of dropped announce requests, because we couldn't keep up
std::atomic<uint32_t> dropped = ATOMIC_VAR_INIT(0);

void gen_secret_digest(sockaddr_in const* from, char* digest)
{
	SHA_CTX ctx = secret;
	SHA1_Update(&ctx, (char*)&from->sin_addr, sizeof(from->sin_addr));
	SHA1_Update(&ctx, (char*)&from->sin_port, sizeof(from->sin_port));
	SHA1_Final((unsigned char*)digest, &ctx);
}

uint64_t generate_connection_id(sockaddr_in const* from)
{
//TODO: add an option to use an insecure, cheap method
	char digest[20];
	gen_secret_digest(from, digest);
	uint64_t ret;
	memcpy((char*)&ret, digest, sizeof(ret));
	return ret;
}

bool verify_connection_id(uint64_t conn_id, sockaddr_in const* from)
{
	char digest[20];
	gen_secret_digest(from, digest);
	return memcmp((char*)&conn_id, digest, sizeof(conn_id)) == 0;
}

void incoming_packet(char const* buf, int size, sockaddr_in const* from, socklen_t fromlen
	, packet_socket& sock, std::vector<announce_thread*>& announce_threads);

// this thread receives incoming announces, parses them and posts
// the announce to the correct announce thread, that then takes over
// and is responsible for responding
void receive_thread(std::vector<announce_thread*>& announce_threads)
{
	sigset_t sig;
	sigfillset(&sig);
	int r = pthread_sigmask(SIG_BLOCK, &sig, NULL);
	if (r == -1)
	{
		fprintf(stderr, "pthread_sigmask failed (%d): %s\n", errno, strerror(errno));
	}

	// this is the sock this thread will use to send responses on
	// to mitigate congestion on the receive socket
	packet_socket sock(true);

	incoming_packet_t pkts[512];

	for (;;)
	{
		int recvd = sock.receive(pkts, sizeof(pkts)/sizeof(pkts[0]));
		if (recvd <= 0) break;
		for (int i = 0; i < recvd; ++i)
			incoming_packet(pkts[i].buffer, pkts[i].buflen, (sockaddr_in*)&pkts[i].from, pkts[0].fromlen
				, sock, announce_threads);
	}
}

void incoming_packet(char const* buf, int size, sockaddr_in const* from, socklen_t fromlen
	, packet_socket& sock, std::vector<announce_thread*>& announce_threads)
{
	bytes_in += size;

//	printf("received message from: %x port: %d size: %d\n"
//		, from->sin_addr.s_addr, ntohs(from->sin_port), size);

	if (size < 16)
	{
		printf("packet too short (%d)\n", size);
		// log incorrect packet
		return;
	}

	udp_announce_message* hdr = (udp_announce_message*)buf;

	switch (ntohl(hdr->action))
	{
		case action_connect:
		{
			if (be64toh(hdr->connection_id) != 0x41727101980LL)
			{
				++errors;
				printf("invalid connection ID for connect message\n");
				// log error
				return;
			}
			udp_connect_response resp;
			resp.action = htonl(action_connect);
			resp.connection_id = generate_connection_id(from);
			resp.transaction_id = hdr->transaction_id;
			++connects;
			iovec iov = { &resp, 16};
			if (sock.send(&iov, 1, (sockaddr*)from, fromlen))
				return;
			break;
		}
		case action_announce:
		{
			if (!verify_connection_id(hdr->connection_id, from))
			{
				printf("invalid connection ID\n");
				++errors;
				// log error
				return;
			}
			// technically the announce message should
			// be 100 bytes, but uTorrent doesn't seem to send
			// the extension field at the end
			if (size < 98)
			{
				printf("announce packet too short. Expected 100, got %d\n", size);
				++errors;
				// log incorrect packet
				return;
			}

			if (!allow_alternate_ip || hdr->ip == 0)
				hdr->ip = from->sin_addr.s_addr;

			// post the announce to the thread that's responsible
			// for this info-hash
			announce_msg m;
			m.bits.announce = *hdr;
			m.from = *from;
			m.fromlen = fromlen;
			int thread_selector = hdr->hash.val[0] % announce_threads.size();
			announce_threads[thread_selector]->post_announce(m);

			break;
		}
		case action_scrape:
		{
			if (!verify_connection_id(hdr->connection_id, from))
			{
				printf("invalid connection ID for connect message\n");
				++errors;
				// log error
				return;
			}
			if (size < 16 + 20)
			{
				printf("scrape packet too short. Expected 36, got %d\n", size);
				++errors;
				// log error
				return;
			}

			udp_scrape_message* req = (udp_scrape_message*)buf;

			// for now, just support scrapes for a single hash at a time
			// to avoid having to bounce the request around all the threads
			// befor accruing all the stats

			// post the announce to the thread that's responsible
			// for this info-hash
			announce_msg m;
			m.bits.scrape = *req;
			m.from = *from;
			m.fromlen = fromlen;
			int thread_selector = req->hash[0].val[0] % announce_threads.size();
			announce_threads[thread_selector]->post_announce(m);

			break;
		}
		default:
			printf("unknown action %d\n", ntohl(hdr->action));
			++errors;
			break;
	}
}

void sigint(int s)
{
	quit = true;
}

int main(int argc, char* argv[])
{
	// TODO: TEMP!
	allow_alternate_ip = true;

	// initialize secret key which the connection-ids are built off of
	uint64_t secret_key = 0;
	for (int i = 0; i < sizeof(secret_key); ++i)
	{
		secret_key <<= 8;
		// TODO: use a c++11 random function instead
		secret_key ^= std::rand();
	}
	SHA1_Init(&secret);
	SHA1_Update(&secret, &secret_key, sizeof(secret_key));

	fprintf(stderr, "listening on UDP port %d\n", listen_port);
	
	std::vector<announce_thread*> announce_threads;
	std::vector<std::thread> receive_threads;

	int num_cores = std::thread::hardware_concurrency();
	if (num_cores == 0) num_cores = 4;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sigint;
	int r = sigaction(SIGINT, &sa, 0);
	if (r == -1)
	{
		fprintf(stderr, "sigaction failed (%d): %s\n", errno, strerror(errno));
		quit = true;
	}
	r = sigaction(SIGTERM, &sa, 0);
	if (r == -1)
	{
		fprintf(stderr, "sigaction failed (%d): %s\n", errno, strerror(errno));
		quit = true;
	}
	if (!quit) fprintf(stderr, "send SIGINT or SIGTERM to quit\n");

	// create threads. We should create the same number of
	// announce threads as we have cores on the machine
	printf("starting %d announce threads\n", num_cores);
#if defined __linux__
	cpu_set_ti* cpu = CPU_ALLOC(std::thread::hardware_concurrency());
#endif
	for (int i = 0; i < num_cores; ++i)
	{
		announce_threads.push_back(new announce_thread());

#if defined __linux__
		std::thread::native_handle_type h = announce_threads.back()->native_handle();
		CPU_CLEAR(cpu);
		CPU_SET(i, cpu);
		pthread_setaffinity_np(h, CPU_ALLOC_SIZE(std::thread::hardware_concurrency()), cpu);
#else
#endif
	}

	printf("starting %d receive threads\n", num_cores);
	for (int i = 0; i < num_cores; ++i)
	{
		receive_threads.push_back(std::thread(receive_thread, std::ref(announce_threads)));
#if defined __linux__
		std::thread::native_handle_type h = receive_threads.back().native_handle();
		CPU_CLEAR(cpu);
		CPU_SET(i, cpu);
		pthread_setaffinity_np(h, CPU_ALLOC_SIZE(std::thread::hardware_concurrency()), cpu);
#else
#endif
	}
#if defined __linux__
	CPU_FREE(cpu);
#endif

	while (!quit)
	{
		std::this_thread::sleep_for(std::chrono::seconds(10));
		uint32_t last_connects = connects.exchange(0);
		uint32_t last_announces = announces.exchange(0);
		uint32_t last_scrapes = scrapes.exchange(0);
		uint32_t last_errors = errors.exchange(0);
		uint32_t last_bytes_in = bytes_in.exchange(0);
		uint32_t last_bytes_out = bytes_out.exchange(0);
		uint32_t last_dropped = dropped.exchange(0);
		printf("c: %u a: %u s: %u e: %u d: %u in: %u kB out: %u kB\n"
			, last_connects / 10, last_announces / 10, last_scrapes / 10, last_errors / 10
			, last_dropped / 10, last_bytes_in / 1000, last_bytes_out / 1000);
	}

	for (std::thread& i : receive_threads)
		i.join();

	for (announce_thread* i : announce_threads)
	{
		delete i;
	}
	announce_threads.clear();

	return EXIT_SUCCESS;
}
