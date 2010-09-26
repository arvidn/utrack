#ifndef _MESSAGES_HPP_
#define _MESSAGES_HPP_

#include <stdint.h>
#include <string.h>

struct sha1_hash
{
	uint32_t val[5];
};

inline bool operator==(sha1_hash const& lhs, sha1_hash const& rhs)
{
	return memcmp(lhs.val, rhs.val, 20) == 0;
}

struct sha1_hash_fun
{
	size_t operator()(sha1_hash const& h) const
	{
		size_t ret = 0;
		for (int i = 0; i < 5; ++i)
		{
			ret ^= h.val[i];
		}
		return ret;
	}
};

enum
{
	max_scrape_responses = 71
};

struct udp_announce_message
{
	uint64_t connection_id;
	uint32_t action;
	uint32_t transaction_id;
	sha1_hash hash;
	sha1_hash peer_id;
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

struct udp_scrape_message
{
	uint64_t connection_id;
	uint32_t action;
	uint32_t transaction_id;
	sha1_hash hash[max_scrape_responses];
};

struct udp_connect_response
{
	uint32_t action;
	uint32_t transaction_id;
	uint64_t connection_id;
};

struct udp_announce_response
{
	uint32_t action;
	uint32_t transaction_id;
	uint32_t interval;
	uint32_t downloaders;
	uint32_t seeds;
};

struct udp_scrape_data
{
	uint32_t downloaders;
	uint32_t download_count;
	uint32_t seeds;
};

struct udp_scrape_response
{
	uint32_t action;
	uint32_t transaction_id;
	udp_scrape_data data[71];
};

enum action_t
{
	action_connect = 0,
	action_announce = 1,
	action_scrape = 2,
	action_error = 3
};

enum event_t
{
	event_none = 0,
	event_completed = 1,
	event_started = 2,
	event_stopped = 3
};

#endif

