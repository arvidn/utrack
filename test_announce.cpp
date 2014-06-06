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

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

sockaddr_in to;

bool send(int socket, char const* buf, int len, sockaddr const* to, socklen_t tolen)
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
	return 0;
}

sha1_hash random_hash()
{
	sha1_hash ret;
	for (int i = 0; i < 5; ++i)
	{
		ret.val[i] = (rand() << 16) ^ rand();
	}
	return ret;
}

int announce_one_peer(int s, int num_peers, uint32_t* ip, sha1_hash const& ih, int event, int action)
{
//	printf("announcing %x on swarm %x event %d\n", ip, ih.val[0], event);

	// use uint64_t to make the buffer properly aligned
	uint64_t buffer[1500/8];

	std::vector<udp_announce_message> reqs(num_peers);

	for (int i = 0; i < num_peers; ++i)
	{
		udp_announce_message& req = reqs[i];
		req.action = htonl(action_connect);
		req.connection_id = be64toh(0x41727101980LL);
		req.transaction_id = (rand() << 16) ^ rand();
		if (send(s, (char*)&req, 16, (sockaddr*)&to, sizeof(to)))
			return 1;
	}

	int len = sizeof(reqs[0]);
	for (int i = 0; i < num_peers; ++i)
	{
		udp_announce_message& req = reqs[i];

		sockaddr from;
		socklen_t fromlen = sizeof(from);
		int r = recvfrom(s, buffer, sizeof(buffer), 0, &from, &fromlen);
		if (r == -1)
		{
			fprintf(stderr, "recvfrom failed (%d): %s\n", errno, strerror(errno));
			return 1;
		}

		udp_connect_response* resp = (udp_connect_response*)buffer;

		req.connection_id = resp->connection_id;
		req.action = htonl(action);
		req.transaction_id = (rand() << 16) ^ rand();
		req.hash = ih;

		if (action == action_scrape)
		{
			len = 16 + 20;
		}
		else
		{
			req.peer_id = random_hash();
			req.downloaded = 0;
			req.left = event == event_started ? htonl(1000) : 0;
			req.uploaded = 0;
			req.event = htonl(event);
			req.ip = ip[i];
			req.key = rand();
			req.num_want = htonl(200);
			req.port = rand();
			req.extensions = 0;
		}

	}

	for (int i = 0; i < num_peers; ++i)
	{
		udp_announce_message& req = reqs[i];
		if (send(s, (char*)&req, len, (sockaddr*)&to, sizeof(to)))
			return 1;
	}

	for (int i = 0; i < num_peers; ++i)
	{
		sockaddr from;
		socklen_t fromlen = sizeof(from);
		int r = recvfrom(s, buffer, sizeof(buffer), 0, &from, &fromlen);
		if (r == -1)
		{
			fprintf(stderr, "recvfrom failed (%d): %s\n", errno, strerror(errno));
			return 1;
		}

		if (action == action_scrape)
		{
			udp_scrape_response* scr = (udp_scrape_response*)buffer;
//			printf("scrape response h: %x d: %u s: %u c: %u\n", ih.val[0]
//				, ntohl(scr->data[0].downloaders)
//				, ntohl(scr->data[0].seeds)
//				, ntohl(scr->data[0].download_count));
		}
	}
	return 0;
}

void* announce_thread(void* arg)
{
	sha1_hash info_hashes[100];
	for (int i = 0; i < sizeof(info_hashes)/sizeof(info_hashes[0]); ++i)
	{
		info_hashes[i] = random_hash();
	}

	uint32_t peer_ips[500];
	for (int i = 0; i < sizeof(peer_ips)/sizeof(peer_ips[0]); ++i)
	{
		peer_ips[i] = (rand() << 16) ^ rand();
	}

	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		fprintf(stderr, "failed to open socket (%d): %s\n"
			, errno, strerror(errno));
		return 0;
	}

	int port = (rand() % 60000) + 2000;
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	printf("binding socket to %d\n", port);
	int r = bind(s, (sockaddr*)&addr, sizeof(addr));
	if (r < 0)
	{
		fprintf(stderr, "failed to bind socket to port %d (%d): %s\n"
			, port, errno, strerror(errno));
		return 0;
	}

	int events[] = { event_started, event_completed, event_stopped };

	for (int e = 0; e < 3; ++e)
	{
//		printf("event: %d\n", e);
		for (int ih = 0; ih < sizeof(info_hashes)/sizeof(info_hashes[0]); ++ih)
		{
			int num_peers = sizeof(peer_ips)/sizeof(peer_ips[0]);
			announce_one_peer(s, num_peers, peer_ips, info_hashes[ih], events[e], action_announce);
			announce_one_peer(s, 1, peer_ips, info_hashes[ih], event_stopped, action_scrape);
		}
	}

done:

	close(s);

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		fprintf(stderr, "usage: ./udp_test address port\n");
		return EXIT_FAILURE;
	}

	int num_threads = 200;

	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	int r = inet_pton(AF_INET, argv[1], &to.sin_addr);
	if (r < 0)
	{
		fprintf(stderr, "invalid target address \"%s\" (%d): %s\n", argv[1]
			, errno, strerror(errno));
		return EXIT_FAILURE;
	}
	to.sin_port = htons(atoi(argv[2]));

	pthread_t* threads = (pthread_t*)malloc(sizeof(pthread_t) * num_threads);
	if (threads == NULL)
	{
		fprintf(stderr, "failed allocate thread list (no memory)\n");
		return EXIT_FAILURE;
	}

	// create threads
	for (int i = 0; i < num_threads; ++i)
	{
		printf("starting thread %d\n", i);
		int r = pthread_create(&threads[i], NULL, &announce_thread, 0);
		if (r != 0)
		{
			fprintf(stderr, "failed to create thread (%d): %s\n", r, strerror(r));
			return EXIT_FAILURE;
		}
	}

	for (int i = 0; i < num_threads; ++i)
	{
		void* retval = 0;
		pthread_join(threads[i], &retval);
		printf("thread %d terminated\n", i);
	}

	free(threads);

	return EXIT_SUCCESS;
}
