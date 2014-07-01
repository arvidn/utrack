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

#ifdef __linux__
#include <sys/ioctl.h> // for SIOCGIFADDR
#else
#include <sys/sockio.h> // for SIOCGIFADDR
#include <net/if_dl.h> // for sockaddr_dl
#endif
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

packet_socket::packet_socket(char const* device, int listen_port)
	: m_pcap(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
#ifndef USE_WINPCAP
	, m_send_cursor(0)
#endif
{
	m_buffer.resize(receive_buffer_size);
#ifndef USE_WINPCAP
	m_send_buffer.resize(send_buffer_size);
#endif

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

	uint32_t ip = 0;
	uint32_t mask = 0;
	r = pcap_lookupnet(device, &ip, &mask, error_msg);
	if (r != 0)
	{
		printf("pcap_lookupnet() = %d \"%s\"\n", r, error_msg);
		exit(1);
	}

	m_our_addr.sin_family = AF_INET;
#if !defined _WIN32 && !defined __linux__
	m_our_addr.sin_len = sizeof(sockaddr_in);
#endif
	m_our_addr.sin_addr.s_addr = ip;
	m_our_addr.sin_port = htons(listen_port);

	m_mask.sin_family = AF_INET;
#if !defined _WIN32 && !defined __linux__
	m_mask.sin_len = sizeof(sockaddr_in);
#endif
	m_mask.sin_addr.s_addr = mask;
	m_mask.sin_port = 0;


#ifdef _WIN32
	ULONG dwSize = 0;
	DWORD dwRetVal;

	std::vector<IP_ADAPTER_ADDRESSES> buffer(10);
	IP_ADAPTER_ADDRESSES *adapters = buffer.data();

	if (GetAdaptersAddresses(AF_UNSPEC
		, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		, nullptr
		, adapters, &dwSize) == ERROR_BUFFER_OVERFLOW)
	{
		buffer.resize((dwSize + sizeof(IP_ADAPTER_ADDRESSES) - 1)/ sizeof(IP_ADAPTER_ADDRESSES));
		adapters = (IP_ADAPTER_ADDRESSES*)buffer.data();
	}

	bool found = false;
	if (memcmp(device, "\\Device\\NPF_", 12) != 0)
	{
		fprintf(stderr, "invalid device name\n");
		exit(1);
	}
	char const* cmp_dev = device + sizeof("\\Device\\NPF_") - 1;
	if ((dwRetVal = GetAdaptersAddresses(AF_UNSPEC
		, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		, nullptr
		, adapters, &dwSize)) == NO_ERROR)
	{
		for (; adapters; adapters = adapters->Next)
		{
			if (strcmp(adapters->AdapterName, cmp_dev) != 0) continue;
			IP_ADAPTER_UNICAST_ADDRESS* unicast = adapters->FirstUnicastAddress;

			while (unicast)
			{
				if (unicast->Address.lpSockaddr->sa_family == AF_INET)
				{
					found = true;
					m_our_addr.sin_addr.s_addr
						= ((sockaddr_in*)unicast->Address.lpSockaddr)->sin_addr.s_addr;
					break;
				}
				unicast = unicast->Next;
			}

			if (found) break;
		}
		if (!found)
		{
			fprintf(stderr, "device not found \"%s\"\n"
				, device);
			exit(1);
		}
	}
	else
	{
		fprintf(stderr, "GetIpAddrTable call failed with %d\n", dwRetVal);
	}


#else
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
		m_our_addr.sin_port = htons(listen_port);
	}
	else
	{
		fprintf(stderr, "get ifaddr = %d \"%s\"\n", r, error_msg);
	}
#endif

	ip = ntohl(m_our_addr.sin_addr.s_addr);
	mask = ntohl(mask);

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

#if defined _WIN32
	// find the ethernet address for device
#elif defined __linux__
	
	{
		ifreq ifr;

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		ifr.ifr_addr.sa_family = AF_INET;
		strcpy(ifr.ifr_name, device);
		ioctl(fd, SIOCGIFHWADDR, &ifr);
		::close(fd);

		memcpy(m_eth_addr.addr, ifr.ifr_hwaddr.sa_data, 6);
	}

#else
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
#endif

	printf("ethernet: ");
	for (int i = 0; i< 6; i++)
		printf(&":%02x"[i == 0], uint8_t(m_eth_addr.addr[i]));
	printf("\n");

	pcap_activate(m_pcap);

	m_link_layer = pcap_datalink(m_pcap);
	if (m_link_layer < 0)
	{
		fprintf(stderr, "pcap_datalink() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
		exit(-1);
	}

	printf("link layer: ");
	switch (m_link_layer)
	{
		case DLT_NULL: printf("loopback\n"); break;
		case DLT_EN10MB: printf("ethernet\n"); break;
		default: printf("unknown\n"); break;
	}

	std::string program_text = "udp";
	if (listen_port != 0)
	{
		program_text += " dst port ";
		program_text += std::to_string(listen_port);

		char buf[100];
		program_text += " and dst host ";
		program_text += inet_ntop(AF_INET, &m_our_addr.sin_addr.s_addr
			, buf, sizeof(buf));
	}

	fprintf(stderr, "capture filter: \"%s\"\n", program_text.c_str());

	bpf_program p;
	r = pcap_compile(m_pcap, &p, program_text.c_str(), 1, 0xffffffff);
	if (r == -1)
		fprintf(stderr, "pcap_compile() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

	r = pcap_setfilter(m_pcap, &p);
	if (r == -1)
		fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));

#ifndef USE_WINPCAP
	for (int i = 0; i < 3; ++i)
		m_send_threads.emplace_back(&packet_socket::send_thread, this);
#endif
}

packet_socket::~packet_socket()
{
	close();
#ifndef USE_WINPCAP
	for (auto& t : m_send_threads) t.join();
#endif
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
#ifdef USE_WINPCAP
	int r = pcap_sendqueue_transmit(m_pcap, packets.m_queue, 0);
	if (r < 0)
		fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
#else
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
#endif
	return true;
}

packet_buffer::packet_buffer(packet_socket& s)
	: m_link_layer(s.m_link_layer)
#ifndef USE_WINPCAP
	, m_send_cursor(0)
#endif
	, m_from(s.m_our_addr)
	, m_mask(s.m_mask)
	, m_eth_from(s.m_eth_addr)
	, m_arp_cache(s.m_arp_cache)
#ifdef USE_WINPCAP
	, m_queue(pcap_sendqueue_alloc(0x100000))
	, m_pcap(s.m_pcap)
#else
	, m_buf(0x100000)
#endif
{}

packet_buffer::~packet_buffer()
{
#ifdef USE_WINPCAP
	pcap_sendqueue_destroy(m_queue);
#endif
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

#ifdef USE_WINPCAP
	std::uint8_t buffer[1500];
	std::uint8_t* ptr = buffer;
	int len = 0;
#else
	if (m_send_cursor + buf_size + 28 + 30 > m_buf.size())
	{
		fprintf(stderr, "packet buffer full\n");
		return false;
	}

	std::uint8_t* ptr = &m_buf[m_send_cursor];

	std::uint8_t* prefix = ptr;
	ptr += 2;

	int len = 0;
#endif

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
			uint32_t dst = to->sin_addr.s_addr;

			// if the address is not part of the local network, set dst to 0
			// to indicate the default route out of our network
			if ((dst & m_mask.sin_addr.s_addr) !=
				(from->sin_addr.s_addr & m_mask.sin_addr.s_addr))
				dst = 0;

			address_eth const& mac = m_arp_cache[dst];

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
			break;
		}
		default:
			// unsupported link layer
			fprintf(stderr, "unsupported data link layer (%d)\n", m_link_layer);
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
#endif

	for (int i = 0; i < num; ++i)
	{
		memcpy(ptr, v[i].iov_base, v[i].iov_len);
		ptr += v[i].iov_len;
		len += v[i].iov_len;
	}

	assert(len <= 1500);
#ifdef USE_WINPCAP
	pcap_pkthdr hdr;
	hdr.caplen = len;
	hdr.len = len;
	memset(&hdr.ts, 0, sizeof(hdr.ts));
	int r = pcap_sendqueue_queue(m_queue, &hdr, buffer);
#else
	prefix[0] = (len >> 8) & 0xff;
	prefix[1] = len & 0xff;

	m_send_cursor += len + 2;
#endif

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
	sockaddr_in local_mask;

	std::unordered_map<uint32_t, address_eth>* arp_cache;
};

void packet_handler(u_char* user, const struct pcap_pkthdr* h
	, const u_char* bytes)
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

	uint8_t const* ethernet_header = bytes;

	uint8_t const* ip_header = bytes + st->link_header_size;

	// we only support IPv4 for now, and no IP options, just
	// the 20 byte header

	// version and length. Ignore any non IPv4 packets and any packets
	// with IP options headers
	if (ip_header[0] != 0x45) {
		fprintf(stderr, "ignoring IP packet version: %d header size: %d\n"
			, ip_header[0] >> 4, (ip_header[0] & 0xf) * 4);
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
	if (st->link_header_size == 14)
	{
		uint32_t dst = from->sin_addr.s_addr;

		// if the address is not part of the local network, set dst to 0
		// to indicate the default route out of our network
		if ((dst & st->local_mask.sin_addr.s_addr) !=
			(st->local_addr.sin_addr.s_addr & st->local_mask.sin_addr.s_addr))
			dst = 0;

		if (st->arp_cache->count(dst) == 0)
		{
			(*st->arp_cache)[dst] = address_eth(ethernet_header + 6);

			uint8_t* ip = (uint8_t*)&dst;
			printf("adding ARP entry: %d.%d.%d.%d -> %02x:%02x:%02x:%02x:%02x:%02x\n"
				, ip[0]
				, ip[1]
				, ip[2]
				, ip[3]
				, ethernet_header[6]
				, ethernet_header[7]
				, ethernet_header[8]
				, ethernet_header[9]
				, ethernet_header[10]
				, ethernet_header[11]
				);
		}
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

#ifndef USE_WINPCAP
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
#endif // !USE_WINPCAP

// fills in the in_packets array with incoming packets. Returns the number filled in
int packet_socket::receive(incoming_packet_t* in_packets, int num)
{
	// TODO: should we just pass in "this" instead? and make it a member
	// function?
	receive_state st;
	st.pkts = in_packets;
	st.len = num;
	st.current = 0;
	st.buffer = m_buffer.data();
	st.buffer_offset = 0;
	st.handle = m_pcap;
	st.local_addr = m_our_addr;
	st.local_mask = m_mask;
	st.arp_cache = &m_arp_cache;

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

void packet_socket::local_endpoint(sockaddr_in* addr)
{
	*addr = m_our_addr;
}

void packet_socket::add_arp_entry(sockaddr_in const* addr
	, address_eth const& mac)
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

