#include "swarm.hpp"

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

void swarm::announce(udp_announce_message* hdr, sockaddr_in const* from, char** buf, int* len
	, uint32_t* downloaders, uint32_t* seeds)
{
	*seeds = m_seeds;
	*downloaders = m_downloaders;

	hash_map4_t::iterator i = m_peers4.find(from->sin_addr.s_addr);

	if (i == m_peers4.end())
	{
		// insert this peer
		peer_entry e;
		e.last_announce = time(0);
		e.index = m_ips4.size();
		e.key = hdr->key;
		if (hdr->event == event_completed)
		{
			e.complete = true;
			++m_download_count;
		}
		if (hdr->left > 0)
		{
			e.downloading = true;
			++m_downloaders;
		}
		else
		{
			e.downloading = false;
			++m_seeds;
		}

		m_ips4.push_back(peer_ip4(from));
		std::pair<hash_map4_t::iterator, bool> ret = m_peers4.insert(
			std::make_pair(from->sin_addr.s_addr, e));
		i = ret.first;
	}
	else
	{
		peer_entry& e = i->second;
		e.last_announce = time(0);
		// TODO: should we prevent peers to change key like this?
		e.key = hdr->key;

		// this peer just completed (and hasn't sent complete before)
		if (hdr->event == event_completed && !e.complete)
		{
			e.complete = true;
			++m_download_count;
		}

		if (hdr->left == 0 && e.downloading)
		{
			// this peer just became a seed
			e.downloading = false;
			--m_downloaders;
			++m_seeds;
		}
		else if (hdr->left > 0 && !e.downloading)
		{
			// this peer just reverted to being a downloader (somehow)
			e.downloading = true;
			--m_seeds;
			++m_downloaders;
		}
	}

	int num_want = (std::min)((std::min)(size_t(200), m_ips4.size()), size_t(hdr->num_want));
	if (num_want == 0)
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
			*len = m_ips4.size() * sizeof(peer_ip4);
		}
		else
		{
			// TODO: this is sub-optimal since it doesn't wrap
			int random = rand() % m_ips4.size();
			*buf = (char*)&m_ips4[random];
			*len = (m_ips4.size() - random) * sizeof(peer_ip4);
		}
	}
}

