#ifndef _SWARM_HPP_
#define _SWARM_HPP_

#include <netinet/in.h>
#include <time.h>

#include "messages.hpp"
#include "hash.hpp"


struct peer_ip4
{
	peer_ip4(sockaddr_in const* addr, uint16_t p)
	{
		// sockaddr is always big endian (network byte order)
		memcpy(&ip, &addr->sin_addr, sizeof(ip));
		memcpy(&port, &p, sizeof(port));
	}
	uint32_t ip4() const
	{
		uint32_t ret;
		memcpy(&ret, ip, sizeof(ip));
		return ret;
	}
	// split up in uint16 to get
	// the compact layout
	uint16_t ip[2];
	uint16_t port;
};

struct peer_entry
{
	peer_entry(): index(0), key(0), last_announce(0), complete(false), downloading(true) {}
	// index into the compact array of IPs
	int index;
	// the key this peer uses in its announces
	// this is used to distinguish between peers
	// on the same IP
	uint32_t key;
	// last time this peer announced
	time_t last_announce;
	// true if we've received complete from this peer
	bool complete:1;
	// true while this peer's left > 0
	bool downloading:1;
};

struct swarm
{
	friend struct swarm_lock;

	swarm();
	~swarm();
	void announce(udp_announce_message* hdr, sockaddr_in const* from, char** buf, int* len
		, uint32_t* downloaders, uint32_t* seeds);
	void scrape(uint32_t* seeds, uint32_t* download_count, uint32_t* downloaders);
private:

	typedef hash_map<uint32_t, peer_entry> hash_map4_t;

	void lock();
	void unlock();

	void erase_peer(swarm::hash_map4_t::iterator i);

	uint32_t m_seeds;
	uint32_t m_downloaders;
	uint32_t m_download_count;

	// the last time anyone announced to this swarm
	// this is used to expire swarms
	time_t m_last_announce;

	// hash table of all peers keyed on their IP
	hash_map4_t m_peers4;

	// compact array of all peers' IPs
	std::vector<peer_ip4> m_ips4;

	// swarm mutex, since it may be accessed
	// by multiple threads, it needs to be locked
	// while accessing it or its peer array
	pthread_mutex_t m_mutex;
};

struct swarm_lock
{
	swarm_lock(swarm& s): m_s(s) { m_s.lock(); }
	~swarm_lock() { m_s.unlock(); }
private:
	// non default constructible and non copyable
	swarm_lock();
	swarm_lock(swarm_lock const&);

	swarm& m_s;
};

#endif

