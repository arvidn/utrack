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

#include "swarm.hpp"
#include "messages.hpp"
#include "endian.hpp"
#include "announce_thread.hpp"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// if this is true, we allow peers to set which IP
// they will announce as. This is off by default since
// it allows for spoofing
bool allow_alternate_ip = false;

int interval = 1800;

int listen_port = 8080;

int num_threads = 4;

int socket_buffer_size = 5 * 1024 * 1024;

// set to true when we're shutting down
volatile bool quit = false;

// this is the UDP socket we accept tracker announces to
int udp_socket = -1;

// partial SHA-1 hash of the secret key, combined with
// source IP and port it forms the connection-id
SHA_CTX secret;

// the address and port we receive packets on, and also
// for sending responses (although over a separate socket)
sockaddr_in bind_addr;

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
//#error add an option to use an insecure, cheap method
	char digest[20];
	gen_secret_digest(from, digest);
	uint64_t ret;
	memcpy((char*)&ret, digest, sizeof(ret));
	return ret;
}

bool verify_connection_id(uint64_t conn_id, sockaddr_in* from)
{
	char digest[20];
	gen_secret_digest(from, digest);
	return memcmp((char*)&conn_id, digest, sizeof(conn_id)) == 0;
}

// send a packet and retry on EINTR
bool respond(int socket, char const* buf, int len, sockaddr const* to, socklen_t tolen)
{
	ssize_t ret = 0;
retry_send:
	ret = sendto(socket, buf, len, MSG_NOSIGNAL, to, tolen);
	if (ret == -1)
	{
		if (errno == EINTR) goto retry_send;
		fprintf(stderr, "sendto failed (%d): %s\n", errno, strerror(errno));
		return 1;
	}
	bytes_out += ret;
	return 0;
}

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

	sockaddr_in from;
	// use uint64_t to make the buffer properly aligned
	uint64_t buffer[1500/8];

	for (;;)
	{
		socklen_t fromlen = sizeof(from);
		int size = recvfrom(udp_socket, (char*)buffer, sizeof(buffer), 0
			, (sockaddr*)&from, &fromlen);
		if (size == -1)
		{
			if (errno == EINTR) continue;
			fprintf(stderr, "recvfrom failed (%d): %s\n", errno, strerror(errno));
			break;
		}
		bytes_in += size;

//		printf("received message from: %x port: %d size: %d\n"
//			, from.sin_addr.s_addr, ntohs(from.sin_port), size);

		if (size < 16)
		{
			printf("packet too short (%d)\n", size);
			// log incorrect packet
			continue;
		}

		udp_announce_message* hdr = (udp_announce_message*)buffer;

		switch (ntohl(hdr->action))
		{
			case action_connect:
			{
				if (be64toh(hdr->connection_id) != 0x41727101980LL)
				{
					++errors;
					printf("invalid connection ID for connect message\n");
					// log error
					continue;
				}
				udp_connect_response resp;
				resp.action = htonl(action_connect);
				resp.connection_id = generate_connection_id(&from);
				resp.transaction_id = hdr->transaction_id;
				++connects;
				if (respond(udp_socket, (char*)&resp, 16, (sockaddr*)&from, fromlen))
					return;
				break;
			}
			case action_announce:
			{
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					printf("invalid connection ID\n");
					++errors;
					// log error
					continue;
				}
				// technically the announce message should
				// be 100 bytes, but uTorrent doesn't seem to send
				// the extension field at the end
				if (size < 98)
				{
					printf("announce packet too short. Expected 100, got %d\n", size);
					++errors;
					// log incorrect packet
					continue;
				}

				if (!allow_alternate_ip || hdr->ip == 0)
					hdr->ip = from.sin_addr.s_addr;

				// post the announce to the thread that's responsible
				// for this info-hash
				announce_msg m;
				m.bits.announce = *hdr;
				m.from = from;
				m.fromlen = fromlen;
				int thread_selector = hdr->hash.val[0] % announce_threads.size();
				announce_threads[thread_selector]->post_announce(m);

				break;
			}
			case action_scrape:
			{
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					printf("invalid connection ID for connect message\n");
					++errors;
					// log error
					continue;
				}
				if (size < 16 + 20)
				{
					printf("scrape packet too short. Expected 36, got %d\n", size);
					++errors;
					// log error
					continue;
				}

				udp_scrape_message* req = (udp_scrape_message*)buffer;

				// for now, just support scrapes for a single hash at a time
				// to avoid having to bounce the request around all the threads
				// befor accruing all the stats

				// post the announce to the thread that's responsible
				// for this info-hash
				announce_msg m;
				m.bits.scrape = *req;
				m.from = from;
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
}

void sigint(int s)
{
	quit = true;
}

int main(int argc, char* argv[])
{
	// TODO: TEMP!
//	allow_alternate_ip = true;

	// initialize secret key which the connection-ids are built off of
	uint64_t secret_key = 0;
	for (int i = 0; i < sizeof(secret_key); ++i)
	{
		secret_key <<= 8;
		secret_key ^= rand();
	}
	SHA1_Init(&secret);
	SHA1_Update(&secret, &secret_key, sizeof(secret_key));

	udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_socket < 0)
	{
		fprintf(stderr, "failed to open socket (%d): %s\n"
			, errno, strerror(errno));
		return EXIT_FAILURE;
	}

	int opt = socket_buffer_size;
	int r = setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
	if (r == -1)
	{
		fprintf(stderr, "failed to set socket receive buffer size (%d): %s\n"
			, errno, strerror(errno));
	}

	int one = 1;
	if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEADDR on socket (%d): %s\n"
			, errno, strerror(errno));
	}

#ifdef SO_REUSEPORT
	if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEPORT on socket (%d): %s\n"
			, errno, strerror(errno));
	}
#endif

	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	bind_addr.sin_port = htons(listen_port);
	r = bind(udp_socket, (sockaddr*)&bind_addr, sizeof(bind_addr));
	if (r < 0)
	{
		fprintf(stderr, "failed to bind socket to port %d (%d): %s\n"
			, listen_port, errno, strerror(errno));
		return EXIT_FAILURE;
	}
	fprintf(stderr, "listening on UDP port %d\n", listen_port);
	
	std::vector<announce_thread*> announce_threads;
	std::vector<std::thread> receive_threads;

	int num_cores = std::thread::hardware_concurrency();
	if (num_cores == 0) num_cores = 4;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sigint;
	r = sigaction(SIGINT, &sa, 0);
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
	for (int i = 0; i < num_cores; ++i)
	{
		printf("starting announce thread %d\n", i);
		announce_threads.push_back(new announce_thread());
	}

	for (int i = 0; i < num_threads; ++i)
	{
		printf("starting receive thread %d\n", i);
		receive_threads.push_back(std::thread(receive_thread, std::ref(announce_threads)));
	}

	while (!quit)
	{
		std::this_thread::sleep_for(std::chrono::seconds(60));
		uint32_t last_connects = connects.exchange(0);
		uint32_t last_announces = announces.exchange(0);
		uint32_t last_scrapes = scrapes.exchange(0);
		uint32_t last_errors = errors.exchange(0);
		uint32_t last_bytes_in = bytes_in.exchange(0);
		uint32_t last_bytes_out = bytes_out.exchange(0);
		uint32_t last_dropped = dropped.exchange(0);
		printf("c: %u a: %u s: %u e: %u d: %u in: %u kB out: %u kB\n"
			, last_connects, last_announces, last_scrapes, last_errors
			, last_dropped, last_bytes_in / 1000, last_bytes_out / 1000);
	}

	close(udp_socket);

	for (std::thread& i : receive_threads)
		i.join();

	for (announce_thread* i : announce_threads)
	{
		delete i;
	}
	announce_threads.clear();

	return EXIT_SUCCESS;
}
