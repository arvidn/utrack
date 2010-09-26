#include "swarm.hpp"
#include <assert.h>

swarm::swarm()
	: m_seeds(0)
	, m_downloaders(0)
	, m_download_count(0)
	, m_last_announce(0)
{
	int r = pthread_mutex_init(&m_mutex, 0);
	if (r != 0)
	{
		fprintf(stderr, "swarm failed to create mutex (%d): %s\n", r, strerror(r));
	}
}

swarm::~swarm()
{
	pthread_mutex_destroy(&m_mutex);
}

void swarm::lock()
{
	pthread_mutex_lock(&m_mutex);
}

void swarm::unlock()
{
	pthread_mutex_unlock(&m_mutex);
}

void swarm::scrape(uint32_t* seeds, uint32_t* download_count, uint32_t* downloaders)
{
	*seeds = m_seeds;
	*download_count = m_download_count;
	*downloaders = m_downloaders;
}

void swarm::announce(udp_announce_message* hdr, char** buf, int* len
	, uint32_t* downloaders, uint32_t* seeds)
{
	*seeds = m_seeds;
	*downloaders = m_downloaders;

	time_t now = time(0);
	m_last_announce = now;

	hash_map4_t::iterator i = m_peers4.find(hdr->ip);

	if (i == m_peers4.end())
	{
		if (ntohl(hdr->event) == event_stopped)
		{
			// we don't have this peer in the list, and it
			// just sent stopped. Don't do anything
			*buf = 0;
			*len = 0;
			return;
		}
		// insert this peer
		peer_entry e;
		e.last_announce = now;
		e.index = m_ips4.size();
		e.key = hdr->key;
		if (ntohl(hdr->event) == event_completed)
		{
			e.complete = true;
			++m_download_count;
		}
		if (ntohl(hdr->left) > 0)
		{
			e.downloading = true;
			++m_downloaders;
		}
		else
		{
			e.downloading = false;
			++m_seeds;
		}

		m_ips4.push_back(peer_ip4(hdr->ip, hdr->port));
		std::pair<hash_map4_t::iterator, bool> ret = m_peers4.insert(
			std::make_pair(hdr->ip, e));
		i = ret.first;
	}
	else
	{
		peer_entry& e = i->second;
		e.last_announce = now;
		// TODO: should we prevent peers to change key like this?
		e.key = hdr->key;

		// this peer just completed (and hasn't sent complete before)
		if (ntohl(hdr->event) == event_completed && !e.complete)
		{
			e.complete = true;
			++m_download_count;
		}

		if (ntohl(hdr->left) == 0 && e.downloading)
		{
			// this peer just became a seed
			e.downloading = false;
			--m_downloaders;
			++m_seeds;
		}
		else if (ntohl(hdr->left) > 0 && !e.downloading)
		{
			// this peer just reverted to being a downloader (somehow)
			e.downloading = true;
			--m_seeds;
			++m_downloaders;
		}

		// the port might have changed
		m_ips4[e.index] = peer_ip4(hdr->ip, hdr->port);
	}

	if (ntohl(hdr->event) == event_stopped)
	{
		// remove the peer from the list and don't
		// return any peers
		erase_peer(i);
		*buf = 0;
		*len = 0;
		return;
	}

	size_t num_want = (std::min)((std::min)(size_t(200)
		, size_t(m_ips4.size())), size_t(ntohl(hdr->num_want)));

	if (num_want <= 0)
	{
		*buf = 0;
		*len = 0;
	}
	else
	{
		if (m_ips4.size() <= num_want)
		{
			// special case when we should send every peer
			*buf = (char*)&m_ips4[0];
			*len = m_ips4.size() * 6;
		}
		else
		{
			// TODO: this is sub-optimal since it doesn't wrap
			int random = rand() % m_ips4.size();
			*buf = (char*)&m_ips4[random];
			*len = (std::min)(m_ips4.size() - random, num_want) * 6;
		}
	}
}

void swarm::erase_peer(swarm::hash_map4_t::iterator i)
{
	peer_entry& e = i->second;
	
	// swap the last entry in the peer IPs array
	// with the one we're removing
	hash_map4_t::iterator last = m_peers4.find(m_ips4.back().ip4());
	assert(i != m_peers4.end());

	last->second.index = e.index;
	m_ips4[e.index] = m_ips4.back();

	// and then remove the last entry
	m_ips4.pop_back();

	if (e.downloading) --m_downloaders;
	else --m_seeds;

	// and finally remove the peer_entry
	m_peers4.erase(i);
}

