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

#include "announce_thread.hpp"
#include <atomic>
#include <chrono>

#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

using std::chrono::steady_clock;
using std::chrono::seconds;

extern std::atomic<uint32_t> bytes_out;
extern std::atomic<uint32_t> announces;
extern std::atomic<uint32_t> dropped;
extern std::atomic<uint32_t> scrapes;

bool respond(int socket, char const* buf, int len, sockaddr const* to, socklen_t tolen);
int create_socket(bool send = true);

void announce_thread::thread_fun()
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
	int sock = create_socket();

	steady_clock::time_point now = steady_clock::now();
	steady_clock::time_point next_prune = now + seconds(10);

	// round-robin for timing out peers
	swarm_map_t::iterator next_to_purge = m_swarms.begin();
	for (;;)
	{
		std::unique_lock<std::mutex> l(m_mutex);
		while (m_queue.empty()
			&& !m_quit
			&& (now = steady_clock::now()) < next_prune)
			m_cond.wait(l);

		if (m_quit) break;
		std::deque<announce_msg> q;
		m_queue.swap(q);
		l.unlock();

		now = steady_clock::now();
		// if it's been long enough, just do some relgular
		// maintanence on the swarms
		if (now > next_prune)
		{
			next_prune = now + seconds(10);

			if (next_to_purge == m_swarms.end() && m_swarms.size() > 0)
				next_to_purge = m_swarms.begin();

			if (m_swarms.size() > 0)
			{
				int num_to_purge = (std::min)(int(m_swarms.size()), 20);

				for (int i = 0; i < num_to_purge; ++i)
				{
					swarm& s = next_to_purge->second;
					s.purge_stale(now);

					++next_to_purge;
					if (next_to_purge == m_swarms.end()) next_to_purge = m_swarms.begin();
				}
			}
		}

		for (announce_msg const& m : q)
		{
			switch (ntohl(m.bits.announce.action))
			{
				case action_announce:
				{
					// find the swarm being announce to
					// or create it if it doesn't exist
					swarm& s = m_swarms[m.bits.announce.hash];

					// prepare the buffer to write the response to
					char* buf;
					int len;
					msghdr msg;
					udp_announce_response resp;

					resp.action = htonl(action_announce);
					resp.transaction_id = m.bits.announce.transaction_id;
					resp.interval = htonl(1680 + rand() * 240 / RAND_MAX);

					// do the actual announce with the swarm
					// and get a pointer to the peers back
					s.announce(now, &m.bits.announce, &buf, &len, &resp.downloaders, &resp.seeds);
					++announces;

					// now turn these counters into network byte order
					resp.downloaders = htonl(resp.downloaders);
					resp.seeds = htonl(resp.seeds);

					// set up the iovec array for the response. The header + the
					// body with the peer list
					iovec iov[2] = { { &resp, 20}, { buf, len } };

					msg.msg_name = (void*)&m.from;
					msg.msg_namelen = m.fromlen;
					msg.msg_iov = iov;
					msg.msg_iovlen = 2;
					msg.msg_control = 0;
					msg.msg_controllen = 0;
					msg.msg_flags = 0;

					// silly loop just to deal with the potential EINTR
					do
					{
						r = sendmsg(sock, &msg, MSG_NOSIGNAL);
						if (r == -1)
						{
							if (errno == EINTR) continue;
							fprintf(stderr, "sendmsg failed (%d): %s\n", errno, strerror(errno));
							return;
						}
						bytes_out += r;
					} while (false);
					break;
				}
			case action_scrape:
				{
					udp_scrape_response resp;
					resp.action = htonl(action_scrape);
					resp.transaction_id = m.bits.scrape.transaction_id;

					++scrapes;

					swarm_map_t::iterator j = m_swarms.find(m.bits.scrape.hash[0]);
					if (j != m_swarms.end())
					{
						j->second.scrape(&resp.data[0].seeds, &resp.data[0].download_count
							, &resp.data[0].downloaders);
						resp.data[0].seeds = htonl(resp.data[0].seeds);
						resp.data[0].download_count = htonl(resp.data[0].download_count);
						resp.data[0].downloaders = htonl(resp.data[0].downloaders);
					}

					if (respond(sock, (char*)&resp, 8 + 12, (sockaddr*)&m.from, m.fromlen))
						return;

					break;
				}
			}
		}
	}

	close(sock);
}

void announce_thread::post_announce(announce_msg const& m)
{
	std::unique_lock<std::mutex> l(m_mutex);

	// have some upper limit here, to avoid
	// allocating memory indefinitely
	if (m_queue.size() >= 5000)
	{
		++dropped;
		return;
	}

	m_queue.push_back(m);

	// don't send a signal if we don't need to
	// it's expensive
	if (m_queue.size() == 1)
		m_cond.notify_one();
}

announce_thread::~announce_thread()
{
	std::unique_lock<std::mutex> l(m_mutex);
	m_quit = true;
	l.unlock();
	m_cond.notify_one();
	m_thread.join();
}

