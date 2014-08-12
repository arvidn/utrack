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

#include <system_error>
#include <stdlib.h> // for exit
#include "utils.hpp"
#include <cstdio> // for snprintf

#ifdef _WIN32

#include <winsock2.h>
#include <iphlpapi.h>

#else

#ifdef __linux__
#include <sys/ioctl.h> // for SIOCGIFADDR
#else
#include <sys/sockio.h> // for SIOCGIFADDR
#include <net/if_dl.h> // for sockaddr_dl
#include <sys/sysctl.h>

#endif // __linux__

#include <arpa/inet.h> // for inet_ntop
#include <netinet/if_ether.h>
#include <net/route.h>

#endif // _WIN32

#include <pcap/pcap.h>

template <typename F>
struct scope_guard
{
	scope_guard(F f) : f(f) {}
	~scope_guard() { f(); }
	F f;
};

template <typename F>
scope_guard<F> make_scope_guard(F f) {
	return scope_guard<F>(f);
};

bool sockaddr_eq(sockaddr const* lhs, sockaddr const* rhs)
{
	if (lhs->sa_family != rhs->sa_family) return false;

	switch (lhs->sa_family)
	{
		case AF_INET:
			return memcmp(&((sockaddr_in*)lhs)->sin_addr
				, &((sockaddr_in*)rhs)->sin_addr, sizeof(sockaddr_in::sin_addr)) == 0;
		case AF_INET6:
			return memcmp(&((sockaddr_in6*)lhs)->sin6_addr
				, &((sockaddr_in6*)rhs)->sin6_addr, sizeof(sockaddr_in6::sin6_addr)) == 0;
		default:
			return false;
	}
}

std::string to_string(sockaddr const* addr)
{
	char buf[256];
	switch(addr->sa_family)
	{
		case AF_INET:
			inet_ntop(AF_INET, &((sockaddr_in*)addr)->sin_addr
				, buf, sizeof(buf));
			return std::string(buf) + ":" + std::to_string(ntohs(((sockaddr_in*)addr)->sin_port));
		case AF_INET6:
			inet_ntop(AF_INET6, &((sockaddr_in6*)addr)->sin6_addr
				, buf, sizeof(buf));
			return "[" + std::string(buf) + "]:" + std::to_string(ntohs(((sockaddr_in6*)addr)->sin6_port));
		default: return "";
	}
}

std::string to_string(address_eth const& addr)
{
	char ret[6*3];
	for (int i = 0; i < 6; i++)
		std::snprintf(&ret[i*3], 4, "%02x:", uint8_t(addr.addr[i]));
	return std::string(ret, 6*3 - 1);
}

// as long ther's still a dependency of pcap_findalldevs
// only have this funtion visible when using it
#if USE_PCAP

std::vector<device_info> interfaces(std::error_code& ec)
{
	std::vector<device_info> ret;

#if defined _WIN32
	// find the ethernet address for device
	PIP_ADAPTER_ADDRESSES adapter_addresses = 0;
	ULONG out_buf_size = 0;
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		| GAA_FLAG_SKIP_ANYCAST, NULL, adapter_addresses, &out_buf_size) != ERROR_BUFFER_OVERFLOW)
	{
		fprintf(stderr, "GetAdaptersAddresses() failed: %d\n", GetLastError());
		ec.assign(GetLastError(), system_category());
		return ret;
	}

	adapter_addresses = (IP_ADAPTER_ADDRESSES*)malloc(out_buf_size);
	if (!adapter_addresses)
	{
		fprintf(stderr, "malloc(%d) failed\n", out_buf_size);
		ec.assign(std:::errc::not_enough_memory);
		return ret;
	}
	auto scope1 = make_scope_guard([=](){free(adapter_addresses);});

	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		| GAA_FLAG_SKIP_ANYCAST, NULL, adapter_addresses, &out_buf_size) != NO_ERROR)
	{
		fprintf(stderr, "GetAdaptersAddresses failed\n", out_buf_size);
		ec.assign(GetLastError(), system_category());
		return ret;
	}

	char const* name = strchr(device, '{');
	for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
		adapter != nullptr; adapter = adapter->Next)
	{
		device_info dev;

		strncpy(dev.name, adapter->AdapterName, sizeof(dev.name));
		memcpy(dev.hardware_addr.addr, adapter->PhysicalAddress, 6);

		for (PIP_ADAPTER_UNICAST_ADDRESS ip = adapter->FirstUnicastAddress;
			ip != nullptr; ip = ip->Next)
		{
			network n;
			n.ip = ip->Address;
			n.mask = ip->Address;
			if (n.mask.sa_family == AF_INET)
			{
				sockaddr_in& mask = (sockaddr_in&)n.mask;
				mask.sin_addr = htonl(0xffffffff >> ip->OnLinkPrefixLength);
			}
			else
			{
				// TODO: support IPv6
				continue;
			}
			dev.networks.push_back(n);
			ret.emplace_back(dev);
		}
	}

	return ret;
#else
	pcap_if_t *alldevs;
	char error_msg[PCAP_ERRBUF_SIZE];

	// TODO: it would be nice to not depend on libpcap for this
	int r = pcap_findalldevs(&alldevs, error_msg);
	if (r != 0)
	{
		printf("pcap_findalldevs() = %d \"%s\"\n", r, error_msg);
		exit(1);
	}
	auto scope1 = make_scope_guard([=](){pcap_freealldevs(alldevs);});

	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
	{
		device_info dev;
		strncpy(dev.name, d->name, IFNAMSIZ);
		for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				network n;
				n.ip = *a->addr;
				n.mask = *a->netmask;
				dev.addresses.push_back(n);
			}

#if !defined __linux__
			// this is how to get the hardware address on BSDs
			if (a->addr->sa_family == AF_LINK && a->addr->sa_data != nullptr)
			{
				sockaddr_dl* link = (struct sockaddr_dl*)a->addr;
				memcpy(dev.hardware_addr.addr, LLADDR(link), 6);
			}
#endif
		}

#if defined __linux__
		// this is how to get the hardware address on linux
		ifreq ifr;
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (r < 0)
		{
			ec.assign(errno, std::system_category());
			return ret;
		}

		ifr.ifr_addr.sa_family = AF_INET;
		strcpy(ifr.ifr_name, dev.name);
		int r = ioctl(fd, SIOCGIFHWADDR, &ifr);
		::close(fd);
		if (r < 0)
		{
			ec.assign(errno, std::system_category());
			return ret;
		}
   
		memcpy(dev.hardware_addr.addr, ifr.ifr_hwaddr.sa_data, 6);
#endif

		ret.emplace_back(dev);
	}

	return ret;
#endif
}

#endif // USE_PCAP

std::vector<arp_entry> arp_table(std::error_code& ec)
{
	std::vector<arp_entry> ret;

#ifdef _WIN32
	MIB_IPNETTABLE* table = 0;
	ULONG out_buf_size = 0;
	if (GetIpNetTable(table, &out_buf_size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
	{
		ec.assign(GetLastError(), std::system_category());
		return ret;
	}

	table = (MIB_IPNETTABLE*)malloc(out_buf_size);
	if (!table)
	{
		ec.assign(std:::errc::not_enough_memory);
		return ret;
	}
	auto scope1 = make_scope_guard([=](){ free(table); });

	if (GetIpNetTable(table, &out_buf_size, FALSE) != NO_ERROR)
	{
		ec.assign(GetLastError(), std::system_category());
		return ret;
	}

	for (int i = 0; i < table->dwNumEntries; ++i)
	{
		arp_entry e;
		memset(&e, 0, sizeof(e));
		sockaddr_in& in = (sockaddr_in&)e.addr;
		in.sin_family = AF_INET;
#if !defined _WIN32 && !defined __linux__
		in.sin_len = sizeof(sockaddr_in);
#endif
		in.sin_addr.s_addr = table->tabls[i].dwAddr;

		assert(table->table[i]->dwPhysAddrLen == 6);
		memcpy(e.hw_addr.addr, table->table[i].bPhysAddr, 6);
		ret.emplace_back(e);
	}

#else
	struct sockaddr_dl *sdl;

	int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
	std::vector<char> buf;

	size_t needed;
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
	{
		ec.assign(errno, std::system_category());
		return ret;
	}

	buf.resize(needed);

	if (sysctl(mib, 6, buf.data(), &needed, NULL, 0) < 0)
	{
		ec.assign(errno, std::system_category());
		return ret;
	}

#define ROUNDUP(a) \
		((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

	char* lim = buf.data() + needed;
	rt_msghdr *rtm;
	for (char* next = buf.data(); next < lim; next += rtm->rtm_msglen) {
		rtm = (rt_msghdr *)next;
		sockaddr_inarp* sin = (sockaddr_inarp *)(rtm + 1);
		sdl = (sockaddr_dl*)((char*)sin + ROUNDUP(sin->sin_len));

		arp_entry e;

		sockaddr_in& in = (sockaddr_in&)e.addr;
		in.sin_family = AF_INET;
#if !defined _WIN32 && !defined __linux__
		in.sin_len = sizeof(sockaddr_in);
#endif
		in.sin_addr = sin->sin_addr;

		memcpy(e.hw_addr.addr, LLADDR(sdl), 6);
		ret.emplace_back(e);
	}
	buf.clear();
#endif // _WIN32

	return ret;
}

