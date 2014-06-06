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

#include "socket.hpp"
#include "config.hpp"

#include <stdio.h> // for stderr
#include <errno.h> // for errno
#include <string.h> // for strerror
#include <stdlib.h> // for exit
#include <unistd.h> // for close
#include <poll.h> // for poll
#include <fcntl.h> // for F_GETFL and F_SETFL
#include <sys/socket.h> // for iovec
#include <assert.h>
#include <netinet/in.h> // for sockaddr

#include <atomic>

#include <pcap/pcap.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

extern std::atomic<uint32_t> bytes_out;

packet_socket::packet_socket(bool receive)
	: m_pcap(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
	, m_send_cursor(0)
{
	char error_msg[PCAP_ERRBUF_SIZE];
	m_pcap = pcap_create("lo0", error_msg);
	if (m_pcap == nullptr)
	{
		fprintf(stderr, "failed to create packet capture handle: %s"
			, error_msg);
		exit(2);
		return;
	}

	// capture whole packets
	pcap_set_snaplen(m_pcap, 1500);

	int r = pcap_setnonblock(m_pcap, 0, error_msg);
	if (r == -1)
	{
		fprintf(stderr, "failed to set blocking mode: %s\n", error_msg);
		return;
	}

	r = pcap_setdirection(m_pcap, PCAP_D_IN);
	if (r == -1)
		fprintf(stderr, "pcap_setdirection() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_set_buffer_size(m_pcap, socket_buffer_size);
	if (r == -1)
		fprintf(stderr, "pcap_set_buffer_size() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_set_timeout(m_pcap, 1);
	if (r == -1)
		fprintf(stderr, "pcap_set_timeout() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_setdirection(m_pcap, PCAP_D_IN);
	if (r == -1)
		fprintf(stderr, "pcap_setdirection() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	pcap_activate(m_pcap);

	m_link_layer = pcap_datalink(m_pcap);
	if (m_link_layer < 0)
		fprintf(stderr, "pcap_datalink() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	bpf_program p;
	r = pcap_compile(m_pcap, &p, "udp dst port 8080", 1, PCAP_NETMASK_UNKNOWN);
	if (r == -1)
		fprintf(stderr, "pcap_compile() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_setfilter(m_pcap, &p);
	if (r == -1)
		fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
}

packet_socket::~packet_socket()
{
	close();
	if (m_pcap)
		pcap_close(m_pcap);
}

void packet_socket::close()
{
	m_closed = 1;
	if (m_pcap)
		pcap_breakloop(m_pcap);
}

bool packet_socket::send(iovec const* v, int num, sockaddr const* to, socklen_t tolen)
{
	int buf_size = 0;
	for (int i = 0; i < num; ++i) buf_size += v[i].iov_len;

	if (buf_size > 1500 - 28 - 30)
	{
		fprintf(stderr, "send: packet too large\n");
		return false;
	}

	std::lock_guard<std::mutex> l(m_mutex);

	if (m_send_cursor + buf_size + 28 + 30 > m_send_buffer.size())
	{
		fprintf(stderr, "send buffer full\n");
		return false;
	}

	std::uint8_t* ptr = &m_send_buffer[m_send_cursor];

	std::uint8_t* prefix = ptr;
	ptr += 2;

	int len = 0;

	switch (m_link_layer)
	{
		case DLT_NULL:
		{
			std::uint32_t proto = 2;
			memcpy(ptr, &proto, 4);
			ptr += 4;
			len += 4;
			break;
		}
		default:
			// unsupported link layer
			fprintf(stderr, "unsupported data link layer\n");
			return false;
	}

	if (to->sa_family != AF_INET)
	{
		fprintf(stderr, "unsupported network protocol (only IPv4 is supported)\n");
		return false;
	}

	sockaddr_in const* sin = (sockaddr_in const*)to;

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
	ip_header[8] = 0x4;

	// protocol
	ip_header[9] = 17;

	// checksum
	ip_header[10] = 0;
	ip_header[11] = 0;

	// from addr
	// TODO: store our IP somewhere so we can insert it here
	memcpy(ip_header + 12, &sin->sin_addr.s_addr, 4);

	// to addr
	memcpy(ip_header + 16, &sin->sin_addr.s_addr, 4);

	// calculate the checksum
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

	extern int listen_port;

	udp_header[0] = listen_port >> 8;
	udp_header[1] = listen_port & 0xff;
	memcpy(&udp_header[2], &sin->sin_port, 2);
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

	m_send_cursor += len + 2;

	return true;
}

struct receive_state
{
	incoming_packet_t* pkts;

	// the total length of the pkts array
	int len;

	// the next slot in pkts to write a packet entry to
	int current;

	// the buffer to copy packets into
	uint64_t* buffer;

	// the offset into m_buffer we have allocated so far. Where we can
	// copy the next incoming packet to
	int buffer_offset;

	pcap_t* handle;

	// the number of bytes to skip in each buffer to get to the IP
	// header.
	int link_header_size;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *h
	, const u_char *bytes)
{
	receive_state* st = (receive_state*)user;

	// TODO: support IPv6 also

	uint8_t const* ip_header = bytes + st->link_header_size;

	// we only support IPv4 for now, and no IP options, just
	// the 20 byte header

	// version and length
	if (ip_header[0] != 0x45) return;

	// flags (ignore any packet with more-fragments set)
	if (ip_header[6] & 0x20) return;

	// ignore any packet with fragment offset
	if ((ip_header[6] & 0x1f) != 0 || ip_header[7] != 0) return;

	// ignore any packet whose transport protocol is not UDP
	if (ip_header[9] != 0x11) return;

	uint8_t const* udp_header = ip_header + 20;

	extern int listen_port;

	// only look at packets to our listen port
	if (((int(udp_header[2]) << 8) | udp_header[3]) != listen_port) return;

	int len = h->caplen - 28 - st->link_header_size;
	bytes += 28 + st->link_header_size;

	incoming_packet_t& pkt = st->pkts[st->current];
	int len8 = (len + 7) / 8;
	if (st->buffer_offset + len8 > buffer_size)
	{
		pcap_breakloop(st->handle);
		return;
	}

	memcpy(&st->buffer[st->buffer_offset], bytes, len);
	pkt.buffer = (char*)&st->buffer[st->buffer_offset];
	pkt.buflen = len;
	st->buffer_offset += len8;

	// copy from IP header
	memset(&pkt.from, 0, sizeof(pkt.from));
	sockaddr_in* from = (sockaddr_in*)&pkt.from;
	from->sin_len = sizeof(sockaddr_in);
	from->sin_family = AF_INET;
	// UDP header: src-port, dst-port, len, chksum
	memcpy(&from->sin_port, udp_header, 2);
	memcpy(&from->sin_addr, ip_header + 12, 4);
	pkt.fromlen = sizeof(sockaddr_in);

	++st->current;
}

void packet_socket::drain_send_queue()
{
	std::lock_guard<std::mutex> l(m_mutex);
	if (m_send_cursor == 0) return;

	for (int i = 0; i < m_send_cursor;)
	{
		int len = (m_send_buffer[i] << 8) | m_send_buffer[i+1];
		assert(len <= 1500);
		assert(len > 0);
		i += 2;
		assert(m_send_buffer.size() - i >= len);

		int r = pcap_sendpacket(m_pcap, &m_send_buffer[i]
			, len);

		if (r == -1)
			fprintf(stderr, "pcap_sendpacket() = %d \"%s\"\n", r
				, pcap_geterr(m_pcap));

		i += len;
	}
	m_send_cursor = 0;
}

// fills in the in_packets array with incoming packets. Returns the number filled in
int packet_socket::receive(incoming_packet_t* in_packets, int num)
{
	receive_state st;
	st.pkts = in_packets;
	st.len = num;
	st.current = 0;
	st.buffer = m_buffer.data();
	st.buffer_offset = 0;
	st.handle = m_pcap;

	switch (m_link_layer)
	{
		case DLT_NULL: st.link_header_size = 4; break;
		default:
			assert(false);
	
	}

	int r;

	bool reset_timeout = false;

	drain_send_queue();

	while (true)
	{
		if (m_closed) return -1;

		r = pcap_dispatch(m_pcap, num, &packet_handler, (uint8_t*)&st);
		if (r < 0)
		{
			fprintf(stderr, "pcap_dispatch() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
			if (r == -3) exit(2);
			return -1;
		}

		drain_send_queue();

		if (st.current != 0) return st.current;

		if (!reset_timeout)
		{
			r = pcap_set_timeout(m_pcap, 100);
			if (r == -1)
				fprintf(stderr, "pcap_set_timeout() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
			reset_timeout = true;
		}
	}

	if (reset_timeout)
	{
		r = pcap_set_timeout(m_pcap, 1);
		if (r == -1)
			fprintf(stderr, "pcap_set_timeout() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
	}
}

