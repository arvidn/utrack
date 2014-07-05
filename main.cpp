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
#ifdef USE_PCAP
		"utrack --list-devices\n\n"
		"   prints available network devices to bind to\n"
		"\n"
#endif
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
#ifdef USE_PCAP
	bool list_devices = false;
	if (argc == 2 && strcmp(argv[1], "--list-devices") == 0)
	{
		list_devices = true;
	}
#endif // USE_PCAP

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

	char const* bind_ip = argv[1];
	int r;

#ifdef USE_PCAP
	char device[200];
	device[0] = '\0';

	pcap_if_t *alldevs;
	char error_msg[PCAP_ERRBUF_SIZE];
	r = pcap_findalldevs(&alldevs, error_msg);
	if (r != 0)
	{
		printf("pcap_findalldevs() = %d \"%s\"\n", r, error_msg);
		exit(1);
	}

	if (alldevs == nullptr)
	{
		printf("no available devices. You may need root privileges\n");
		exit(1);

	}

	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
	{
		if (list_devices)
			printf("%s\n", d->name);

		for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next)
		{
			char buf[100];
			switch (a->addr->sa_family)
			{
				case AF_INET:
					inet_ntop(AF_INET
						, &((sockaddr_in*)a->addr)->sin_addr, buf, sizeof(buf));
					if (list_devices)
						printf("   %s\n", buf);
					if (strcmp(buf, bind_ip) == 0)
						strcpy(device, d->name);
					break;
				case AF_INET6:
					inet_ntop(AF_INET6
						, &((sockaddr_in6*)a->addr)->sin6_addr, buf, sizeof(buf));
					if (list_devices)
						printf("   %s\n", buf);
					if (strcmp(buf, bind_ip) == 0)
						strcpy(device, d->name);
					break;
			}
		}
	}
	pcap_freealldevs(alldevs);

	if (list_devices) return 0;

	if (device[0] == '\0')
	{
		fprintf(stderr, "no device with ip: %s\nuse --list-devices to list them\n"
			, bind_ip);
		return 1;
	}

	printf("listening on UDP port %d on device %s\n"
		, listen_port, device);
#else
	printf("listening on UDP port %d on IP %s\n"
		, listen_port, bind_ip);
#endif
	
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

#ifdef USE_PCAP
	packet_socket socket(device, listen_port);
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
#endif
	for (int i = 0; i < num_cores; ++i)
	{
#ifdef USE_PCAP
		announce_threads.push_back(new announce_thread(socket));
#else
		announce_threads.push_back(new announce_thread(listen_port));
#endif

#if defined __linux__
		std::thread::native_handle_type h = announce_threads.back()->native_handle();
		CPU_ZERO(cpu);
		CPU_SET(i, cpu);
		int r = pthread_setaffinity_np(h, CPU_ALLOC_SIZE(num_cores), cpu);
		if (r != 0)
		{
			fprintf(stderr, "pthread_setaffinity() = %d: (%d) %s\n"
				, r, errno, strerror(errno));
			exit(1);
		}
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
		receive_threads.push_back(new receive_thread(listen_port, announce_threads));
#endif

#if defined __linux__
		std::thread::native_handle_type h = receive_threads.back()->native_handle();
		CPU_ZERO(cpu);
		CPU_SET(i, cpu);
		int r = pthread_setaffinity_np(h, CPU_ALLOC_SIZE(num_cores), cpu);
		if (r != 0)
		{
			fprintf(stderr, "pthread_setaffinity() = %d: (%d) %s\n"
				, r, errno, strerror(errno));
			exit(1);
		}
#endif
	}

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

#if defined __linux__
	CPU_FREE(cpu);
#endif
	return EXIT_SUCCESS;
}
