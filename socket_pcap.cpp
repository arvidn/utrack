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
#include <net/if.h> // for ifreq
#include <sys/sockio.h> // for SIOCGIFADDR
#include <sys/ioctl.h>
#include <net/if_dl.h> // for sockaddr_dl

#include <atomic>
#include <mutex>
#include <chrono>
#include <thread>

#include <pcap/pcap.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

extern std::atomic<uint32_t> bytes_out;

packet_socket::packet_socket(char const* device, int listen_port)
	: m_pcap(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
	, m_send_cursor(0)
{
	m_send_buffer.resize(send_buffer_size);

	char error_msg[PCAP_ERRBUF_SIZE];
	m_pcap = pcap_create(device, error_msg);
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

	ifreq req;
	strncpy(req.ifr_name, device, IFNAMSIZ);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		fprintf(stderr, "socket() = %d \"%s\"\n", r, strerror(errno));
		exit(-1);
	}
	r = ioctl(s, SIOCGIFADDR, &req);
	::close(s);

	if (r == 0)
	{
		sockaddr_in* our_ip = (sockaddr_in*)&req.ifr_addr;
		if (our_ip->sin_family != AF_INET)
		{
			fprintf(stderr, "device \"%s\" is not supported\n", device);
			exit(-1);
		}
		m_our_addr = *our_ip;
	}
	else
	{
		fprintf(stderr, "get ifaddr = %d \"%s\"\n", r, error_msg);
		m_our_addr.sin_addr.s_addr = 0;
	}

	m_our_addr.sin_port = htons(listen_port);

	uint32_t host_ip = ntohl(m_our_addr.sin_addr.s_addr);
	printf("bound to %d.%d.%d.%d\n"
		, (host_ip >> 24) & 0xff
		, (host_ip >> 16) & 0xff
		, (host_ip >> 8) & 0xff
		, host_ip & 0xff);

	pcap_if_t *alldevs;
	r = pcap_findalldevs(&alldevs, error_msg);
	if (r != 0)
	{
		printf("pcap_findalldevs() = %d \"%s\"\n", r, error_msg);
		exit(1);
	}

	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
	{
		if (strcmp(d->name, device) != 0) continue;
		for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next)
		{
			if (a->addr->sa_family != AF_LINK || a->addr->sa_data == nullptr)
				continue;

			sockaddr_dl* link = (struct sockaddr_dl*)a->addr;

			memcpy(m_eth_addr.addr, LLADDR(link), 6);
			break;
		}
	}
	pcap_freealldevs(alldevs);

	printf("ethernet: ");
	for (int i = 0; i< 6; i++)
		printf(&":%02x"[i == 0], uint8_t(m_eth_addr.addr[i]));
	printf("\n");

	pcap_activate(m_pcap);

	m_link_layer = pcap_datalink(m_pcap);
	if (m_link_layer < 0)
		fprintf(stderr, "pcap_datalink() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	// TODO: it would be nice to be able to bind to a specific
	// IP too, not just port
	char program_text[100];
	char const* format_string = "udp dst port %d";
	if (listen_port == 0) format_string = "udp";
	snprintf(program_text, sizeof(program_text), format_string, listen_port);
	bpf_program p;
	r = pcap_compile(m_pcap, &p, program_text, 1, PCAP_NETMASK_UNKNOWN);
	if (r == -1)
		fprintf(stderr, "pcap_compile() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_setfilter(m_pcap, &p);
	if (r == -1)
		fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	for (int i = 0; i < 3; ++i)
		m_send_threads.emplace_back(&packet_socket::send_thread, this);
}

packet_socket::~packet_socket()
{
	close();
	for (auto& t : m_send_threads) t.join();
	if (m_pcap) pcap_close(m_pcap);
}

void packet_socket::close()
{
	m_closed = 1;
	if (m_pcap)
		pcap_breakloop(m_pcap);
}

bool packet_socket::send(packet_buffer& packets)
{
	std::lock_guard<std::mutex> l(m_mutex);

	if (packets.m_send_cursor == 0) return true;

	if (m_send_cursor + packets.m_send_cursor > m_send_buffer.size())
	{
		printf("(dropping %d kiB)\n"
			, packets.m_send_cursor / 1024);
		packets.m_send_cursor = 0;
		return false;
	}

	bytes_out += packets.m_send_cursor;

	memcpy(&m_send_buffer[m_send_cursor]
		, packets.m_buf.data(), packets.m_send_cursor);

	m_send_cursor += packets.m_send_cursor;
	packets.m_send_cursor = 0;
	return true;
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

	if (m_send_cursor + buf_size + 28 + 30 > m_buf.size())
	{
		fprintf(stderr, "packet buffer full\n");
		return false;
	}

	std::uint8_t* ptr = &m_buf[m_send_cursor];

	std::uint8_t* prefix = ptr;
	ptr += 2;

	int len = 0;

#ifdef USE_SYSTEM_SEND_SOCKET
	memcpy(ptr, to, sizeof(sockaddr_in));
	ptr += sizeof(sockaddr_in);
	len += sizeof(sockaddr_in);
#else
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
		case DLT_EN10MB:
		{
			// TODO: figure out how to fill in the destination MAC
			// destination MAC address
			memset(ptr, 0, 6);
			// source MAC address
			memcpy(ptr + 6, m_eth_from.addr, 6);
			// ethertype (upper layer protocol)
			// 0x0800 = IPv4
			// 0x86dd = IPv6
			ptr[12] = 0x08;
			ptr[13] = 0x00;
			ptr += 14;
			len += 14;
			break;
		}
		default:
			// unsupported link layer
			fprintf(stderr, "unsupported data link layer\n");
			return false;
	}

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
	ip_header[8] = 0x4;

	// protocol
	ip_header[9] = 17;

	// checksum
	ip_header[10] = 0;
	ip_header[11] = 0;

	// from addr
	memcpy(ip_header + 12, &from->sin_addr.s_addr, 4);

	// to addr
	memcpy(ip_header + 16, &to->sin_addr.s_addr, 4);

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

	memcpy(&udp_header[0], &from->sin_port, 2);
	memcpy(&udp_header[2], &to->sin_port, 2);
	udp_header[4] = (buf_size + 8) >> 8;
	udp_header[5] = (buf_size + 8) & 0xff;

	// UDP checksum
	udp_header[6] = 0;
	udp_header[7] = 0;

	ptr += 8;
	len += 8;
#endif

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

	// ignore packets sent to other addresses and ports than this one.
	// a port of 0 means accept packets on any port
	sockaddr_in local_addr;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *h
	, const u_char *bytes)
{
	receive_state* st = (receive_state*)user;

	if (st->current >= st->len)
	{
		fprintf(stderr, "receive iov full (%d) (why is this callback still being called?)\n"
			, st->current);
		pcap_breakloop(st->handle);
		return;
	}

	// TODO: support IPv6 also

	uint8_t const* ip_header = bytes + st->link_header_size;

	// we only support IPv4 for now, and no IP options, just
	// the 20 byte header

	// version and length. Ignore any non IPv4 packets and any packets
	// with IP options headers
	if (ip_header[0] != 0x45) return;

	// flags (ignore any packet with more-fragments set)
	if (ip_header[6] & 0x20) return;

	// ignore any packet with fragment offset
	if ((ip_header[6] & 0x1f) != 0 || ip_header[7] != 0) return;

	// ignore any packet whose transport protocol is not UDP
	if (ip_header[9] != 0x11) return;

	uint8_t const* udp_header = ip_header + 20;

	// only look at packets to our listen port
	if (st->local_addr.sin_port != 0 &&
		memcmp(&udp_header[2], &st->local_addr.sin_port, 2) != 0)
		return;

	// only look at packets sent to the IP we bound to
	// address 0 means any address
	if (st->local_addr.sin_addr.s_addr != 0 &&
		memcmp(&st->local_addr.sin_addr.s_addr, ip_header + 16, 4) != 0)
		return;

	int len = h->caplen - 28 - st->link_header_size;
	bytes += 28 + st->link_header_size;

	if (len > 1500)
	{
		fprintf(stderr, "incoming packet too large\n");
		return;
	}

	incoming_packet_t& pkt = st->pkts[st->current];
	int len8 = (len + 7) / 8;

	assert(st->buffer_offset + len8 <= receive_buffer_size);

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

	++st->current;

	// if we won't fit another full packet, break the loop and deliver the
	// packets we have so far to the user, then resume reading more packets
	if (st->buffer_offset + 1500/8 > receive_buffer_size)
	{
		pcap_breakloop(st->handle);
		return;
	}
}

void packet_socket::send_thread()
{
	std::vector<uint8_t> local_buffer;
	local_buffer.resize(send_buffer_size);
	int end;

#ifdef USE_SYSTEM_SEND_SOCKET
	// socket used for sending
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		fprintf(stderr, "failed to open send socket (%d): %s\n"
			, errno, strerror(errno));
		exit(1);
	}
	int one = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEADDR on send socket (%d): %s\n"
			, errno, strerror(errno));
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
	{
		fprintf(stderr, "failed to set SO_REUSEPORT on send socket (%d): %s\n"
			, errno, strerror(errno));
	}
#endif
	sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	bind_addr.sin_port = m_our_addr.sin_port;
	int r = bind(sock, (sockaddr*)&bind_addr, sizeof(bind_addr));
	if (r < 0)
	{
		fprintf(stderr, "failed to bind send socket to port %d (%d): %s\n"
			, ntohs(m_our_addr.sin_port), errno, strerror(errno));
		exit(1);
	}

	int opt = socket_buffer_size;
	r = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
	if (r == -1)
	{
		fprintf(stderr, "failed to set send socket buffer size (%d): %s\n"
			, errno, strerror(errno));
	}
#endif

	// exponential back-off. The more read operations that return
	// no packets, the longer we wait until we read again. This
	// balances CPU usage when idle with wasting less time when busy
	const static int sleep_timers[] = {0, 1, 5, 10, 50, 100, 500};
	int sleep = 0;
	while (!m_closed)
	{
		if (sleep > 0)
		{
			// we did not see any packets in the buffer last cycle
			// through. sleep for a while to see if there are any in
			// a little bit
//			printf("sleep %d ms\n", sleep_timers[sleep-1]);
			std::this_thread::sleep_for(std::chrono::milliseconds(sleep_timers[sleep-1]));
		}

		{
			std::lock_guard<std::mutex> l(m_mutex);
			if (m_send_cursor == 0)
			{
				if (sleep < sizeof(sleep_timers)/sizeof(sleep_timers[0]))
					++sleep;
				continue;
			}

			local_buffer.swap(m_send_buffer);

			end = m_send_cursor;
			m_send_cursor = 0;
		}

		sleep = 0;

		for (int i = 0; i < end;)
		{
			int len = (local_buffer[i] << 8) | local_buffer[i+1];
			assert(len <= 1500);
			assert(len > 0);
			i += 2;
			assert(local_buffer.size() - i >= len);

#ifdef USE_SYSTEM_SEND_SOCKET
			assert(len >= sizeof(sockaddr_in));
			sockaddr_in* to = (sockaddr_in*)(local_buffer.data() + i);
			int r = sendto(sock
				, local_buffer.data() + i + sizeof(sockaddr_in)
				, len - sizeof(sockaddr_in), 0, (sockaddr*)to, sizeof(sockaddr_in));
			if (r == -1)
				fprintf(stderr, "sendto() = %d \"%s\"\n", r
					, strerror(errno));
#else
			int r = pcap_sendpacket(m_pcap, local_buffer.data() + i
				, len);

			if (r == -1)
				fprintf(stderr, "pcap_sendpacket() = %d \"%s\"\n", r
					, pcap_geterr(m_pcap));
#endif

			i += len;
		}
	}

#ifdef USE_SYSTEM_SEND_SOCKET
	::close(sock);
#endif
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
	st.local_addr = m_our_addr;

	switch (m_link_layer)
	{
		case DLT_NULL: st.link_header_size = 4; break;
		case DLT_EN10MB: st.link_header_size = 14; break;
		default:
			assert(false);
	}

	int r;

	bool reset_timeout = false;

	while (true)
	{
		if (m_closed) return -1;

		r = pcap_dispatch(m_pcap, num - st.current, &packet_handler, (uint8_t*)&st);

		if (r == -1)
		{
			fprintf(stderr, "pcap_dispatch() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
			if (r == -3) exit(2);
			return -1;
		}

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

