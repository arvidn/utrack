#ifndef _SWARM_HPP_
#define _SWARM_HPP_

#include <netinet/in.h>
#include <time.h>
#include <vector>
#include <thread>
#include <unordered_map>

#include "messages.hpp"


struct peer_ip4
{
	peer_ip4(uint32_t addr, uint16_t p)
	{
		// addr is always big endian (network byte order)
		memcpy(&ip, &addr, sizeof(ip));
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
	peer_entry(): index(0), complete(false), downloading(true), key(0), last_announce(0) {}
	// index into the compact array of IPs
	uint32_t index:30;
	// true if we've received complete from this peer
	bool complete:1;
	// true while this peer's left > 0
	bool downloading:1;
	// the key this peer uses in its announces
	// this is used to distinguish between peers
	// on the same IP
	uint32_t key;
	// last time this peer announced
	time_t last_announce;
};

struct swarm
{
	swarm();
	void announce(udp_announce_message const* hdr, char** buf, int* len
		, uint32_t* downloaders, uint32_t* seeds);
	void scrape(uint32_t* seeds, uint32_t* download_count, uint32_t* downloaders);

	void purge_stale(time_t now);

private:

	typedef std::unordered_map<uint32_t, peer_entry> hash_map4_t;

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

	// the last peer we checked for purgine stale peers
	// this may be m_peers4.end(). It's used to not
	// necessarily go through all peers in one go
	hash_map4_t::iterator m_last_purge;
};

#endif

