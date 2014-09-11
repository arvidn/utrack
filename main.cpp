/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2010-2014  Arvid Norberg

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

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntop
#include <unistd.h>
#else
#include <winsock2.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <thread>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <deque>
#include <system_error>

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

using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::seconds;

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
std::atomic<uint32_t> dropped_bytes_out = ATOMIC_VAR_INIT(0);

// the number of dropped announce requests, because we couldn't keep up
std::atomic<uint32_t> dropped_announces = ATOMIC_VAR_INIT(0);

#ifdef _WIN32
BOOL WINAPI sigint(DWORD s)
#else
void sigint(int s)
#endif
{
	printf("shutting down\n");
	quit = true;

#ifdef _WIN32
	return TRUE;
#endif
}

void print_usage()
{
	printf("usage:\nutrack bind-ip [port]\n\n"
		"   bind-ip      the IP address of the network device to listen on\n"
		"   port         the UDP port to listen on (defaults to 80)\n"
		"\n"
		"utrack --help\n\n"
		"   displays this message\n"
		);
	exit(1);
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
	if (argc == 2 && strcmp(argv[1], "--help") == 0)
		print_usage();

	if (argc > 3 || argc < 2) print_usage();

	int listen_port = 80;
	if (argc > 2)
		listen_port = atoi(argv[2]);

	if (listen_port == 0)
	{
		fprintf(stderr, "cannot listen on port 0\n");
		exit(1);
	}

	sockaddr_in bind_addr;
	bind_addr.sin_family = AF_INET;
#if !defined _WIN32 && !defined __linux__
	bind_addr.sin_len = sizeof(sockaddr_in);
#endif
	bind_addr.sin_port = htons(listen_port);

	int r = inet_pton(AF_INET, argv[1], &bind_addr.sin_addr);
	if (r != 1)
	{
		fprintf(stderr, "invalid bind address:\"%s\"\n", argv[1]);
		exit(1);
	}

	std::vector<announce_thread*> announce_threads;
	std::vector<receive_thread*> receive_threads;

	int num_cores = std::thread::hardware_concurrency();
	if (num_cores == 0) num_cores = 4;

#ifndef _WIN32
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
	if (!quit) printf("send SIGINT or SIGTERM to quit\n");
#else
	if (SetConsoleCtrlHandler(&sigint, TRUE) == FALSE)
	{
		std::error_code ec(GetLastError(), std::system_category());
		fprintf(stderr, "failed to register Ctrl-C handler: (%d) %s\n"
			, ec.value(), ec.message().c_str());
	}
#endif

#if defined USE_PCAP || defined USE_NETMAP
	packet_socket socket((sockaddr const*)&bind_addr);
#endif

	// create threads. We should create the same number of
	// announce threads as we have cores on the machine
	printf("starting %d announce threads\n", num_cores);
#if defined __linux__
	cpu_set_t* cpu = CPU_ALLOC(num_cores);
	if (cpu == nullptr)
	{
		fprintf(stderr, "CPU_ALLOC failed!\n");
		exit(1);
	}
	int cpu_size = CPU_ALLOC_SIZE(num_cores);
#endif
	for (int i = 0; i < num_cores; ++i)
	{
#if defined USE_PCAP || defined USE_NETMAP
		announce_threads.push_back(new announce_thread(socket));
#else
		announce_threads.push_back(new announce_thread(listen_port));
#endif

#if defined __linux__
		std::thread::native_handle_type h = announce_threads.back()->native_handle();
		CPU_ZERO_S(cpu_size, cpu);
		CPU_SET_S(i, cpu_size, cpu);
		int r = pthread_setaffinity_np(h, CPU_ALLOC_SIZE(num_cores), cpu);
		if (r != 0)
		{
			fprintf(stderr, "pthread_setaffinity() = %d: (%d) %s\n"
				, r, errno, strerror(errno));
			exit(1);
		}
#endif
	}

#if defined USE_PCAP || defined USE_NETMAP
	const int num_receive_threads = 1;
#else
	const int num_receive_threads = num_cores;
#endif
	printf("starting %d receive threads\n", num_receive_threads);
	for (int i = 0; i < num_receive_threads; ++i)
	{
#if defined USE_PCAP || defined USE_NETMAP
		receive_threads.push_back(new receive_thread(socket, announce_threads));
#else
		receive_threads.push_back(new receive_thread(listen_port, announce_threads));
#endif

#if defined __linux__
		std::thread::native_handle_type h = receive_threads.back()->native_handle();
		CPU_ZERO_S(cpu_size, cpu);
		CPU_SET_S(i, cpu_size, cpu);
		int r = pthread_setaffinity_np(h, CPU_ALLOC_SIZE(num_cores), cpu);
		if (r != 0)
		{
			fprintf(stderr, "pthread_setaffinity() = %d: (%d) %s\n"
				, r, errno, strerror(errno));
			exit(1);
		}
#endif
	}

	int counter = 0;
	while (!quit)
	{
		// print column headings every 20 lines
		if ((counter % 20) == 0)
		{
			printf("%-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s\n"
				, "conns/s", "announce/s", "scrape/s", "errors/s", "drop/s"
				, "in (kB/s)", "out (kB/s)", "drop(kB/s)");
		}

		++counter;

		steady_clock::time_point start = steady_clock::now();
		std::this_thread::sleep_for(seconds(10));
		steady_clock::duration d = steady_clock::now() - start;
		int sec = duration_cast<seconds>(d).count();

		uint32_t last_connects = connects.exchange(0);
		uint32_t last_announces = announces.exchange(0);
		uint32_t last_scrapes = scrapes.exchange(0);
		uint32_t last_errors = errors.exchange(0);
		uint32_t last_bytes_in = bytes_in.exchange(0);
		uint32_t last_bytes_out = bytes_out.exchange(0);
		uint32_t last_dropped_bytes_out = dropped_bytes_out.exchange(0);
		uint32_t last_dropped_announces = dropped_announces.exchange(0);
		printf("%10u %10u %10u %10u %10u %10u %10u %10u\n"
			, last_connects / sec
			, last_announces / sec
			, last_scrapes / sec
			, last_errors / sec
			, last_dropped_announces / sec
			, last_bytes_in / 1000 / sec
			, last_bytes_out / 1000 / sec
			, last_dropped_bytes_out / 1000 / sec);
		keys.tick();
	}

	for (receive_thread* i : receive_threads)
		i->close();

	for (receive_thread* i : receive_threads)
		delete i;

	for (announce_thread* i : announce_threads)
		delete i;

#if defined __linux__
	CPU_FREE(cpu);
#endif
	return EXIT_SUCCESS;
}
