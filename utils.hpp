/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2014 Arvid Norberg

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

#ifndef UTILS_HPP_
#define UTILS_HPP_

#include <system_error>
#include <vector>
#include <string>

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <net/if.h>
#endif

struct address_eth
{
	address_eth() { memset(addr, 0, sizeof(addr)); }
	address_eth(address_eth const& a) = default;
	explicit address_eth(uint8_t const* ptr) { memcpy(addr, ptr, sizeof(addr)); }
	uint8_t addr[6];
};

struct network
{
	sockaddr ip;
	sockaddr mask;
};

struct device_info
{
	char name[IFNAMSIZ];
	address_eth hardware_addr;
	std::vector<network> addresses;
};

struct arp_entry
{
	sockaddr addr;
	address_eth hw_addr;
};

std::vector<device_info> interfaces(std::error_code& ec);

std::vector<arp_entry> arp_table(std::error_code& ec);

bool sockaddr_eq(sockaddr const* lhs, sockaddr const* rhs);
std::string to_string(sockaddr const* addr);
std::string to_string(address_eth const& addr);

#endif

