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
	// This is a no-op. The sending is done when adding
	// to the packet_buffer
	return true;
}

packet_buffer::packet_buffer(packet_socket& s)
	: m_link_layer(s.m_link_layer)
	, m_from(s.m_our_addr)
	, m_mask(s.m_mask)
	, m_eth_from(s.m_eth_addr)
	, m_arp(s)
{
}

packet_buffer::~packet_buffer()
{
}

bool packet_buffer::append(iovec const* v, int num
	, sockaddr_in const* to)
{
	return append_impl(v, num, to, &m_from);
}

bool packet_buffer::append_impl(iovec const* v, int num
	, sockaddr_in const* to, sockaddr_in const* from)
{
	int buf_size = 0;
	for (int i = 0; i < num; ++i) buf_size += v[i].iov_len;

	if (buf_size > 1500 - 28 - 30)
	{
		fprintf(stderr, "append: packet too large\n");
		return false;
	}

	std::uint8_t buf[1500];
	std::uint8_t* ptr = buf;

	std::uint8_t* prefix = ptr;
	ptr += 2;

	int len = 0;

	address_eth const& mac = m_arp.lookup(from, to, &m_mask);

	memcpy(ptr, mac.addr, 6);
	// source MAC address
	memcpy(ptr + 6, m_eth_from.addr, 6);
	// ethertype (upper layer protocol)
	// 0x0800 = IPv4
	// 0x86dd = IPv6
	ptr[12] = 0x08;
	ptr[13] = 0x00;
	ptr += 14;
	len += 14;

	if (to->sin_family != AF_INET)
	{
		fprintf(stderr, "unsupported network protocol (only IPv4 is supported)\n");
		return false;
	}

	std::uint8_t* ip_header = ptr;

	// version and header length
	ip_header[0] = (4 << 4) | 5;
	// DSCP and ECN
	ip_header[1] = 0;

	// packet length
	ip_header[2] = (buf_size + 20 + 8) >> 8;
	ip_header[3] = (buf_size + 20 + 8) & 0xff;

	// identification
	ip_header[4] = 0;
	ip_header[5] = 0;

	// fragment offset and flags
	ip_header[6] = 0;
	ip_header[7] = 0;

	// TTL
	ip_header[8] = 0x80;

	// protocol
	ip_header[9] = 17;

	// checksum
	ip_header[10] = 0;
	ip_header[11] = 0;

	// from addr
	memcpy(ip_header + 12, &from->sin_addr.s_addr, 4);

	// to addr
	memcpy(ip_header + 16, &to->sin_addr.s_addr, 4);

	// calculate the IP checksum
	std::uint16_t chk = 0;
	for (int i = 0; i < 20; i += 2)
	{
		chk += (ip_header[i] << 8) | ip_header[i+1];
	}
	chk = ~chk;

	ip_header[10] = chk >> 8;
	ip_header[11] = chk & 0xff;

	ptr += 20;
	len += 20;

	std::uint8_t* udp_header = ip_header + 20;

	if (from->sin_port == 0)
	{
		// we need to make up a source port here if our
		// listen port is 0 (i.e. in "promiscuous" mode)
		// this essentially only happens in the load test
		uint16_t port = htons(6881);
		memcpy(&udp_header[0], &port, 2);
	}
	else
	{
		memcpy(&udp_header[0], &from->sin_port, 2);
	}
	memcpy(&udp_header[2], &to->sin_port, 2);
	udp_header[4] = (buf_size + 8) >> 8;
	udp_header[5] = (buf_size + 8) & 0xff;

	// UDP checksum
	udp_header[6] = 0;
	udp_header[7] = 0;

	ptr += 8;
	len += 8;

	for (int i = 0; i < num; ++i)
	{
		memcpy(ptr, v[i].iov_base, v[i].iov_len);
		ptr += v[i].iov_len;
		len += v[i].iov_len;
	}

	assert(len <= 1500);
	prefix[0] = (len >> 8) & 0xff;
	prefix[1] = len & 0xff;

	int r = nm_inject(m_hw_rings, buf, len + 2);
	if (r == 0)
	{
		dropped_bytes_out.fetch_add(buf_size, std::memory_order_relaxed);
		return false;
	}

	return true;
}

struct receive_state
{
	incoming_packet_t* pkts;

	// the total length of the pkts array
	int len;

	// the next slot in pkts to write a packet entry to
	int current;

	packet_socket* self;
};

void packet_handler::packet_handler(u_char* user, const struct pcap_pkthdr* h
	, const u_char* bytes)
{
	receive_state* st = (receive_state*)user;

	if (st->current >= st->len)
	{
		fprintf(stderr, "receive iov full (%d) (why is this callback still being called?)\n"
			, st->current);
		return;
	}

	// TODO: support IPv6 also

	uint8_t const* ethernet_header = bytes;

	uint8_t const* ip_header = bytes + st->link_header_size;

	// we only support IPv4 for now, and no IP options, just
	// the 20 byte header

	// version and length. Ignore any non IPv4 packets and any packets
	// with IP options headers
	if (ip_header[0] != 0x45) {
		// this is noisy, don't print out for every IPv6 packet
//		fprintf(stderr, "ignoring IP packet version: %d header size: %d\n"
//			, ip_header[0] >> 4, (ip_header[0] & 0xf) * 4);
		return;
	}

	// flags (ignore any packet with more-fragments set)
	if (ip_header[6] & 0x20) {
		fprintf(stderr, "ignoring fragmented IP packet\n");
		return;
	}

	// ignore any packet with fragment offset
	if ((ip_header[6] & 0x1f) != 0 || ip_header[7] != 0) {
		fprintf(stderr, "ignoring fragmented IP packet\n");
		return;
	}

	// ignore any packet whose transport protocol is not UDP
	if (ip_header[9] != 0x11) {
		fprintf(stderr, "ignoring non UDP packet (protocol: %d)\n"
			, ip_header[9]);
		return;
	}

	uint8_t const* udp_header = ip_header + 20;

	// only look at packets to our listen port
	if (st->local_addr.sin_port != 0 &&
		memcmp(&udp_header[2], &st->local_addr.sin_port, 2) != 0)
	{
		fprintf(stderr, "ignoring packet not to our port (port: %d)\n"
			, ntohs(*(uint16_t*)(udp_header+2)));
		return;
	}

	// only look at packets sent to the IP we bound to
	// port 0 means any address
	if (st->local_addr.sin_port != 0 &&
		memcmp(&st->local_addr.sin_addr.s_addr, ip_header + 16, 4) != 0)
	{
		fprintf(stderr, "ignoring packet not to our address (%d.%d.%d.%d)\n"
			, ip_header[16]
			, ip_header[17]
			, ip_header[18]
			, ip_header[19]);
		return;
	}

	int payload_len = h->caplen - 28 - st->link_header_size;
	uint8_t const* payload = bytes + 28 + st->link_header_size;

	if (payload_len > 1500)
	{
		fprintf(stderr, "incoming packet too large\n");
		return;
	}

	incoming_packet_t& pkt = st->pkts[st->current];
	int len8 = (payload_len + 7) / 8;

	assert(st->buffer_offset + len8 <= receive_buffer_size);

	memcpy(&st->buffer[st->buffer_offset], payload, payload_len);
	pkt.buffer = (char*)&st->buffer[st->buffer_offset];
	pkt.buflen = payload_len;
	st->buffer_offset += len8;

	// copy from IP header
	memset(&pkt.from, 0, sizeof(pkt.from));
	sockaddr_in* from = (sockaddr_in*)&pkt.from;
#if !defined _WIN32 && !defined __linux__
	from->sin_len = sizeof(sockaddr_in);
#endif
	from->sin_family = AF_INET;
	// UDP header: src-port, dst-port, len, chksum
	memcpy(&from->sin_port, udp_header, 2);
	memcpy(&from->sin_addr, ip_header + 12, 4);

	// ETHERNET
	if (st->arp->has_entry(&st->local_addr, from, &st->local_mask) == 0)
	{
		st->arp->add_arp_entry(from, address_eth(ethernet_header + 6));
	}

	++st->current;

	// if we won't fit another full packet, break the loop and deliver the
	// packets we have so far to the user, then resume reading more packets
	if (st->buffer_offset + 1500/8 > receive_buffer_size)
	{
		pcap_breakloop(st->handle);
		return;
	}
}

void packet_socket::local_endpoint(sockaddr_in* addr)
{
	*addr = m_our_addr;
}

