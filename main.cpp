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
#include "endian.hpp"
#include "announce_thread.hpp"
#include "socket.hpp"
#include "key_rotate.hpp"
#include "receive_thread.hpp"
#include "config.hpp"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int interval = default_interval;

// set to true when we're shutting down
volatile bool quit = false;

// the secret keys used for syn-cookies
key_rotate keys;

// stats counters
std::atomic<uint32_t> connects = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> announces = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> scrapes = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> errors = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> bytes_out = ATOMIC_VAR_INIT(0);
std::atomic<uint32_t> bytes_in = ATOMIC_VAR_INIT(0);

// the number of dropped announce requests, because we couldn't keep up
std::atomic<uint32_t> dropped = ATOMIC_VAR_INIT(0);

void sigint(int s)
{
	quit = true;
}

void print_usage()
{
	printf("usage: utrack device [port]\n\n"
		"device       the network device to listen on\n"
		"port         the UDP port to listen on (defaults to 80)\n"
		);
	exit(1);
}

int main(int argc, char* argv[])
{
	if (argc > 3 || argc < 2) print_usage();

	int listen_port = 80;
	if (argc > 2)
		listen_port = atoi(argv[2]);

	if (listen_port == 0)
	{
		fprintf(stderr, "cannot listen on port 0\n");
		exit(1);
	}

	char const* device = argv[1];
	fprintf(stderr, "listening on UDP port %d on device %s\n"
		, listen_port, device);
	
	std::vector<announce_thread*> announce_threads;
	std::vector<receive_thread*> receive_threads;

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

#ifdef USE_PCAP
	packet_socket socket(device, listen_port);
#endif

	// create threads. We should create the same number of
	// announce threads as we have cores on the machine
	printf("starting %d announce threads\n", num_cores);
#if defined __linux__
	cpu_set_ti* cpu = CPU_ALLOC(num_cores);
#endif
	for (int i = 0; i < num_cores; ++i)
	{
#ifdef USE_PCAP
		announce_threads.push_back(new announce_thread(socket));
#else
		announce_threads.push_back(new announce_thread);
#endif

#if defined __linux__
		std::thread::native_handle_type h = announce_threads.back()->native_handle();
		CPU_CLEAR(cpu);
		CPU_SET(i, cpu);
		pthread_setaffinity_np(h, CPU_ALLOC_SIZE(num_cores), cpu);
#else
#endif
	}

#ifdef USE_PCAP
	const int num_receive_threads = 1;
#else
	const int num_receive_threads = num_cores;
#endif
	printf("starting %d receive threads\n", num_receive_threads);
	for (int i = 0; i < num_receive_threads; ++i)
	{
#ifdef USE_PCAP
		receive_threads.push_back(new receive_thread(socket, announce_threads));
#else
		receive_threads.push_back(new receive_thread(announce_threads));
#endif

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
		printf("c: %u a: %u s: %u e: %u d: %u in: %u kB/s out: %u kB/s\n"
			, last_connects / 10, last_announces / 10, last_scrapes / 10, last_errors / 10
			, last_dropped / 10, last_bytes_in / 10000, last_bytes_out / 10000);
		keys.tick();
	}

	for (receive_thread* i : receive_threads)
		i->close();

	for (receive_thread* i : receive_threads)
		delete i;

	for (announce_thread* i : announce_threads)
		delete i;

	return EXIT_SUCCESS;
}
