/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2013-2014 Arvid Norberg

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

#include <unordered_map>
#include <cassert>

struct arp_cache
{
	void add_arp_entry(sockaddr_in const* addr, address_eth const& mac)
	{
		uint8_t* ip = (uint8_t*)&addr->sin_addr.s_addr;
		printf("adding ARP entry: %d.%d.%d.%d -> %02x:%02x:%02x:%02x:%02x:%02x\n"
			, ip[0]
			, ip[1]
			, ip[2]
			, ip[3]
			, mac.addr[0]
			, mac.addr[1]
			, mac.addr[2]
			, mac.addr[3]
			, mac.addr[4]
			, mac.addr[5]
			);

		m_arp_cache[addr->sin_addr.s_addr] = mac;
	}

	bool has_entry(sockaddr_in const* from
		, sockaddr_in const* to
		, sockaddr_in const* mask) const
	{
		uint32_t dst = to->sin_addr.s_addr;
		uint32_t src = from->sin_addr.s_addr;
		uint32_t m = mask->sin_addr.s_addr;

		// if the address is not part of the local network, set dst to 0
		// to indicate the default route out of our network
		if ((dst & m) != (src & m))
			dst = 0;

		return m_arp_cache.count(dst) > 0;
	}

	address_eth const& lookup(sockaddr_in const* from
		, sockaddr_in const* to
		, sockaddr_in const* mask) const
	{

		uint32_t dst = to->sin_addr.s_addr;
		uint32_t src = from->sin_addr.s_addr;
		uint32_t m = mask->sin_addr.s_addr;

		// if the address is not part of the local network, set dst to 0
		// to indicate the default route out of our network
		if ((dst & m) != (src & m))
			dst = 0;

		auto i = m_arp_cache.find(dst);
		assert(i != m_arp_cache.end());
		return i->second;
	}

private:

	// maps local IPs (IPs masked by the network mask)
	// to the corresponding ethernet address (MAC address)
	std::unordered_map<uint32_t, address_eth> m_arp_cache;
};

