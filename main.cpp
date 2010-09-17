/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2010  Arvid Norberg

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

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// this is the UDP socket we accept tracker announces to
int udp_socket = -1;

struct udp_tracker_message
{
	uint64_t connection_id;
	uint32_t action;
	uint32_t transaction_id;
	uint8_t hash[20];
	uint8_t peer_id[20];
	int64_t downloaded;
	int64_t left;
	int64_t uploaded;
	int32_t event;
	uint32_t ip;
	uint32_t key;
	int32_t num_want;
	uint16_t port;
	uint16_t extensions;
};

struct udp_tracker_response
{
	uint32_t action;
	uint32_t transaction_id;
	uint64_t connection_id;
};

enum action_t
{
	action_connect = 0,
	action_announce = 1,
	action_scrape = 2,
	action_error = 3
};

SHA_CTX secret;

void gen_secret_digest(sockaddr_in const* from, char* digest)
{
	SHA_CTX ctx = secret;
	SHA1_Update(&ctx, (char*)&from->sin_addr, sizeof(from->sin_addr));
	SHA1_Update(&ctx, (char*)&from->sin_port, sizeof(from->sin_port));
	SHA1_Final((unsigned char*)digest, &ctx);
}

uint64_t generate_connection_id(sockaddr_in const* from)
{
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
	ret = sendto(udp_socket, buf, len, MSG_NOSIGNAL, to, tolen);
	if (ret == -1)
	{
		if (errno == EINTR) goto retry_send;
		fprintf(stderr, "sendto failed (%d): %s\n", errno, strerror(errno));
		return 1;
	}
	return 0;
}

void* tracker_thread(void* arg)
{
	sockaddr_in from;
	// use uint64_t to make the buffer properly aligned
	uint64_t buffer[1500/8];

	for (;;)
	{
		socklen_t fromlen;
		int size = recvfrom(udp_socket, (char*)buffer, sizeof(buffer), 0
			, (sockaddr*)&from, &fromlen);
		if (size == -1)
		{
			if (errno == EINTR) continue;
			fprintf(stderr, "recvfrom failed (%d): %s\n", errno, strerror(errno));
			break;
		}

		udp_tracker_message* hdr = (udp_tracker_message*)buffer;

		switch (hdr->action)
		{
			case action_connect:
				if (hdr->connection_id != 0x41727101980LL)
				{
					// log error
					continue;
				}
				udp_tracker_response resp;
				resp.action = action_connect;
				resp.connection_id = generate_connection_id(&from);
				resp.transaction_id = hdr->transaction_id;
				if (respond(udp_socket, (char*)&resp, sizeof(resp), (sockaddr*)&from, fromlen))
					return 0;
				break;
			case action_announce:
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					// log error
					continue;
				}
				break;
			case action_scrape:
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					// log error
					continue;
				}
				break;
			default:
				continue;
		}

	}

}

int main(int argc, char* argv[])
{
	// initialize secret key which the connection-ids are built off of
	uint64_t secret_key = 0;
	for (int i = 0; i < sizeof(secret_key); ++i)
	{
		secret_key <<= 8;
		secret_key ^= rand();
	}
	SHA1_Init(&secret);
	SHA1_Update(&secret, &secret_key, sizeof(secret_key));

	int listen_port = 8080;
	int num_threads = 4;

	sigset_t sig;
	sigfillset(&sig);
	int r = sigprocmask(SIG_BLOCK, &sig, NULL);
	if (r == -1)
	{
		fprintf(stderr, "sigprocmask failed (%d): %s\n", errno, strerror(errno));
	}

	udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_socket < 0)
	{
		fprintf(stderr, "failed to open socket (%d): %s\n"
			, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(listen_port);
	r = bind(udp_socket, (sockaddr*)&addr, sizeof(addr));
	if (r < 0)
	{
		fprintf(stderr, "failed to bind socket to port %d (%d): %s\n"
			, listen_port, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	pthread_t* threads = (pthread_t*)malloc(sizeof(pthread_t) * num_threads);
	if (threads == NULL)
	{
		fprintf(stderr, "failed allocate thread list (no memory)\n");
		exit(EXIT_FAILURE);
	}

	// create threads
	for (int i = 0; i < num_threads; ++i)
	{
		r = pthread_create(&threads[i], NULL, &tracker_thread, 0);
		if (r != 0)
		{
			fprintf(stderr, "failed to create thread (%d): %s\n", r, strerror(r));
			exit(EXIT_FAILURE);
		}
	}

	sigemptyset(&sig);
	sigaddset(&sig, SIGTERM);
	int received_signal;
	r = sigwait(&sig, &received_signal);
	if (r == -1)
	{
		fprintf(stderr, "sigwait failed (%d): %s\n", errno, strerror(errno));
	}

	close(udp_socket);

	for (int i = 0; i < num_threads; ++i)
	{
		void* retval = 0;
		pthread_join(threads[i], &retval);
	}

	free(threads);

	return EXIT_SUCCESS;
}
