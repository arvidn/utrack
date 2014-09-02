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

#include "socket.hpp"
#include "config.hpp"
#include "utils.hpp"

#include <stdio.h> // for stderr
#include <errno.h> // for errno
#include <string.h> // for strerror
#include <stdlib.h> // for exit
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define snprintf _snprintf
#else
#include <unistd.h> // for close
#include <poll.h> // for poll
#include <fcntl.h> // for F_GETFL and F_SETFL
#include <sys/socket.h> // for iovec
#include <netinet/in.h> // for sockaddr
#include <net/if.h> // for ifreq
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntop

#endif

#include <atomic>
#include <mutex>
#include <chrono>
#include <thread>
#include <string>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

extern std::atomic<uint32_t> bytes_out;
extern std::atomic<uint32_t> dropped_bytes_out;

packet_socket::packet_socket(char const* device)
	: m_hw_rings(nullptr)
	, m_sw_rings(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
{
	std::error_code ec;
	std::vector<device_info> devices = interfaces(ec);
	if (ec)
	{
		fprintf(stderr, "failed to list network interfaces: \"%s\"\n"
			, ec.message().c_str());
		exit(2);
	}

	// resolve source IP and network mask from device
	bool found = false;
	for (auto const& dev : devices)
	{
		printf("device: %s\n", dev.name);
		printf("  hw: %s\n", to_string(dev.hardware_addr).c_str());
		if (strcmp(dev.name, device) != 0) continue;

		// just pick the first IPv4 address
		auto i = std::find_if(dev.addresses.begin(), dev.addresses.end()
			, [=](network const& a) { return a.ip.sa_family == AF_INET; });

		if (i == dev.addresses.end())
		{
			fprintf(stderr, "could not find an IPv4 address on device: \"%s\"\n"
				, device);
			exit(2);
		}

		found = true;
		m_eth_addr = dev.hardware_addr;
		m_mask = (sockaddr_in&)i->mask;
		m_our_addr = (sockaddr_in&)i->ip;
	}

	if (!found)
	{
		fprintf(stderr, "could not find device: \"%s\"\n", device);
		exit(2);
	}

	init(device);
}

packet_socket::packet_socket(sockaddr const* bind_addr)
	: m_hw_rings(nullptr)
	, m_sw_rings(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
{
	if (bind_addr->sa_family != AF_INET)
	{
		fprintf(stderr, "only IPv4 supported\n");
		exit(2);
		return;
	}

	m_our_addr = *(sockaddr_in*)bind_addr;

	std::error_code ec;
	std::vector<device_info> devices = interfaces(ec);
	if (ec)
	{
		fprintf(stderr, "failed to list network interfaces: \"%s\"\n"
			, ec.message().c_str());
		exit(2);
	}

	// resolve device and network mask from bind_addr
	char device[IFNAMSIZ];
	bool found = false;
	for (auto const& dev : devices)
	{
		printf("device: %s\n", dev.name);
		printf("  hw: %s\n", to_string(dev.hardware_addr).c_str());

		auto i = std::find_if(dev.addresses.begin(), dev.addresses.end()
			, [=](network const& a) { return sockaddr_eq(&a.ip, (sockaddr const*)&m_our_addr); });

		if (i == dev.addresses.end()) continue;

		found = true;
		m_eth_addr = dev.hardware_addr;
		m_mask = (sockaddr_in&)i->mask;
		strncpy(device, dev.name, IFNAMSIZ);
	}

	if (!found)
	{
		fprintf(stderr, "failed to bind: no device found with that address\n");
		exit(2);
	}

	init(device);
}

void packet_socket::init(char const* device)
{
	char netmap_device[200];
	snprintf(netmap_device, sizeof(netmap_device), "netmap:%s", device);
	m_hw_rings = nm_open(netmap_device, nullptr, 0, nullptr);
	if (m_hw_rings == nullptr)
	{
		fprintf(stderr, "failed to bind netmap hardware port: %s"
			, std::error_code(errno, std::system_category()).message().c_str());
		exit(2);
	}

	m_sw_rings = nm_open("netmap:^", nullptr, 0, nullptr);
	if (m_sw_rings == nullptr)
	{
		fprintf(stderr, "failed to bind netmap software stack port: %s"
			, std::error_code(errno, std::system_category()).message().c_str());
		exit(2);
	}

	uint32_t ip = ntohl(m_our_addr.sin_addr.s_addr);
	uint32_t mask = ntohl(m_mask.sin_addr.s_addr);

	printf("bound to %d.%d.%d.%d\n"
		, (ip >> 24) & 0xff
		, (ip >> 16) & 0xff
		, (ip >> 8) & 0xff
		, ip & 0xff);

	printf("mask %d.%d.%d.%d\n"
		, (mask >> 24) & 0xff
		, (mask >> 16) & 0xff
		, (mask >> 8) & 0xff
		, mask & 0xff);

	printf("hw: %s\n", to_string(m_eth_addr).c_str());
	printf("hardware-rings: %d\n", m_hw_rings->req.nr_rx_rings);
}

packet_socket::~packet_socket()
{
	close();

	// close receive and transmit rings
	if (m_hw_rings)
		nm_close(m_hw_rings);
	if (m_sw_rings)
		nm_close(m_sw_rings);
}

void packet_socket::close()
{
	m_closed = 1;
}

bool packet_socket::send(packet_buffer& packets)
{
	ioctl(m_hw_rings->fd, NIOCTXSYNC, NULL);
	return true;
}

bool packet_socket::append_impl(iovec const* v, int num
	, sockaddr_in const* to, sockaddr_in const* from)
{
	int buf_size = 0;
	for (int i = 0; i < num; ++i) buf_size += v[i].iov_len;

	if (buf_size > 1500 - 28 - 30)
	{
		fprintf(stderr, "append: packet too large\n");
		return false;
	}

	if (to->sin_family != AF_INET)
	{
		fprintf(stderr, "unsupported network protocol (only IPv4 is supported)\n");
		return false;
	}

	std::uint8_t buf[1500];
	std::uint8_t* ptr = buf;
	int len = 0;

	int r = render_eth_frame(ptr, 1500 - len, to, from, &m_mask
		, m_eth_addr, *this);
	if (r < 0) return false;
	ptr += len;
	len += r;

	r = render_ip_frame(ptr, 1500 - len, v, num, to, from);

	if (r < 0) return false;
	len += r;

	r = nm_inject(m_hw_rings, buf, len + 2);
	if (r == 0)
	{
		dropped_bytes_out.fetch_add(buf_size, std::memory_order_relaxed);
		return false;
	}

	return true;
}

bool packet_socket::is_full(int buf_size) const
{
	// loop over all transmit rings. If a single of them has some space,
	// we're not full
	for (int i = m_hw_rings->cur_tx_ring; i <= m_hw_rings->last_tx_ring; ++i) {
		netmap_ring* tx_ring = NETMAP_TXRING(m_hw_rings->nifp, i);
		if (!nm_ring_empty(tx_ring)) return false;
	}
	return true;
}

packet_buffer::packet_buffer(packet_socket& s)
	: m_sock(s)
{
}

bool packet_buffer::append(iovec const* v, int num
	, sockaddr_in const* to)
{
	return m_sock.append_impl(v, num, to, &m_sock.m_our_addr);
}

bool packet_buffer::append_impl(iovec const* v, int num
	, sockaddr_in const* to, sockaddr_in const* from)
{
	return m_sock.append_impl(v, num, to, from);
}

bool packet_buffer::is_full(int buf_size) const
{
	return m_sock.is_full(buf_size);
}

void packet_socket::local_endpoint(sockaddr_in* addr)
{
	*addr = m_our_addr;
}

