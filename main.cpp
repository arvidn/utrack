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

#include "hash.hpp"
#include "swarm.hpp"
#include "messages.hpp"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// TODO: TEMP
#define ntohll(x) (x)

// this is the UDP socket we accept tracker announces to
int udp_socket = -1;

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

pthread_rwlock_t swarm_mutex;
typedef hash_map<sha1_hash, swarm*, sha1_hash_fun> swarm_map_t;
swarm_map_t swarms;

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
	return 0;
}

void* tracker_thread(void* arg)
{
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

//		printf("received message from: %x port: %d size: %d\n"
//			, from.sin_addr.s_addr, ntohs(from.sin_port), size);

		if (size < 16)
		{
			// log incorrect packet
			continue;
		}

		udp_announce_message* hdr = (udp_announce_message*)buffer;

		switch (hdr->action)
		{
			case action_connect:
			{
				if (ntohll(hdr->connection_id) != 0x41727101980LL)
				{
					// log error
					continue;
				}
				udp_connect_response resp;
				resp.action = action_connect;
				resp.connection_id = generate_connection_id(&from);
				resp.transaction_id = hdr->transaction_id;
				if (respond(udp_socket, (char*)&resp, sizeof(resp), (sockaddr*)&from, fromlen))
					return 0;
				break;
			}
			case action_announce:
			{
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					// log error
					continue;
				}
				if (size < sizeof(udp_announce_message))
				{
					// log incorrect packet
					continue;
				}

				pthread_rwlock_rdlock(&swarm_mutex);
				swarm_map_t::iterator i = swarms.find(hdr->hash);
				swarm* s = 0;
				if (i != swarms.end())
				{
					s = i->second;
				}
				pthread_rwlock_unlock(&swarm_mutex);

				if (s == 0)
				{
					// the swarm doesn't exist, we need to add it
					s = new swarm;

					pthread_rwlock_wrlock(&swarm_mutex);
					swarms.insert(std::make_pair(hdr->hash, s));
					pthread_rwlock_unlock(&swarm_mutex);
				}

				char* buf;
				int len;
				iovec iov[2];
				msghdr msg;
				udp_announce_response resp;

				resp.action = action_announce;
				resp.connection_id = hdr->connection_id;
				resp.transaction_id = hdr->transaction_id;
				resp.interval = 1680 + rand() * 240 / RAND_MAX;

				msg.msg_name = (void*)&from;
				msg.msg_namelen = fromlen;
				msg.msg_iov = iov;
				msg.msg_iovlen = 2;
				msg.msg_control = 0;
				msg.msg_controllen = 0;
				msg.msg_flags = 0;

				iov[0].iov_base = &resp;
				iov[0].iov_len = sizeof(resp);

				swarm_lock l(*s);
				s->announce(hdr, &from, &buf, &len, &resp.downloaders, &resp.seeds);

				iov[1].iov_base = buf;
				iov[1].iov_len = len;

				// silly loop just to deal with the potential EINTR
				do
				{
					int r = sendmsg(udp_socket, &msg, MSG_NOSIGNAL);
					if (r == -1)
					{
						if (errno == EINTR) continue;
						fprintf(stderr, "sendmsg failed (%d): %s\n", errno, strerror(errno));
						return 0;
					}
				} while (false);
				break;
			}
			case action_scrape:
			{
				if (!verify_connection_id(hdr->connection_id, &from))
				{
					// log error
					continue;
				}
				if (size < 16 + 20)
				{
					// log error
					continue;
				}

				// if someone sent a very large scrape request, only
				// respond to the first ones. We don't want to lock
				// too many swarms for just one response
				int num_hashes = (std::min)((size - 16) / 20, int(max_scrape_responses));

				udp_scrape_message* req = (udp_scrape_message*)buffer;

				udp_scrape_response resp;
				resp.action = action_announce;
				resp.connection_id = hdr->connection_id;
				resp.transaction_id = hdr->transaction_id;

				pthread_rwlock_rdlock(&swarm_mutex);
				for (int i = 0; i < num_hashes; ++i)
				{
					swarm_map_t::iterator j = swarms.find(req->hash[i]);
					if (j != swarms.end())
					{
						swarm* s = j->second;
						swarm_lock l(*s);
						s->scrape(&resp.data[i].seeds, &resp.data[i].download_count
							, &resp.data[i].downloaders);
					}
				}
				pthread_rwlock_unlock(&swarm_mutex);

				if (respond(udp_socket, (char*)&resp, 16 + num_hashes * 20, (sockaddr*)&from, fromlen))
					return 0;

				break;
			}
			default:
				continue;
		}
	}
	return 0;
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
	int num_threads = 1;

	sigset_t sig;
	sigfillset(&sig);
	int r = sigprocmask(SIG_BLOCK, &sig, NULL);
	if (r == -1)
	{
		fprintf(stderr, "sigprocmask failed (%d): %s\n", errno, strerror(errno));
	}

	r = pthread_rwlock_init(&swarm_mutex, 0);
	if (r != 0)
	{
		fprintf(stderr, "pthread_rwlock_init failed (%d): %s\n", r, strerror(r));
		exit(EXIT_FAILURE);
	}

	udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_socket < 0)
	{
		fprintf(stderr, "failed to open socket (%d): %s\n"
			, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(addr);
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
		printf("starting thread %d\n", i);
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
	else
	{
		puts("received SIGTERM, shutting down\n");
	}

	close(udp_socket);

	for (int i = 0; i < num_threads; ++i)
	{
		void* retval = 0;
		pthread_join(threads[i], &retval);
		printf("thread %d terminated\n", i);
	}

	free(threads);

	pthread_rwlock_destroy(&swarm_mutex);

	return EXIT_SUCCESS;
}
