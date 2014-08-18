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
#include "utils.hpp"
#include "stack.hpp"

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
	: m_pcap(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
#ifndef USE_WINPCAP
	, m_send_cursor(0)
#endif
{
#ifdef USE_WINPCAP
	m_send_buffer.reserve(21);
#else
	m_send_buffer.resize(send_buffer_size);
#endif

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
	: m_pcap(nullptr)
	, m_closed(ATOMIC_VAR_INIT(0))
#ifndef USE_WINPCAP
	, m_send_cursor(0)
#endif
{
#ifdef USE_WINPCAP
	m_send_buffer.reserve(21);
#else
	m_send_buffer.resize(send_buffer_size);
#endif

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

	r = pcap_activate(m_pcap);
	if (r != 0)
	{
		fprintf(stderr, "pcap_activate() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
		exit(-1);
	}

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
	if (m_our_addr.sin_port != 0)
	{
		program_text += " dst port ";
		program_text += std::to_string(ntohs(m_our_addr.sin_port));

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

	for (int i = 0; i < 3; ++i)
		m_send_threads.emplace_back(&packet_socket::send_thread, this);
}

packet_socket::~packet_socket()
{
	close();
	for (auto& t : m_send_threads) t.join();
#ifdef USE_WINPCAP
	for (auto i : m_free_list)
		pcap_sendqueue_destroy(i);
	for (auto i : m_send_buffer)
		pcap_sendqueue_destroy(i);
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
	assert(packets.m_queue != 0);
	std::unique_lock<std::mutex> l(m_mutex);
	if (m_send_buffer.size() > 20)
	{
		l.unlock();

		// if the send queue is too large, just send
		// it synchronously
		int r = pcap_sendqueue_transmit(m_pcap, packets.m_queue, 0);
		if (r < 0)
			fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
		return true;
	}

	assert(packets.m_queue != NULL);
	m_send_buffer.push_back(packets.m_queue);
	if (!m_free_list.empty())
	{
		packets.m_queue = m_free_list.back();
		m_free_list.erase(m_free_list.end()-1);
	}
	else
	{
		l.unlock();
		packets.m_queue = pcap_sendqueue_alloc(0x100000);
		if (packets.m_queue == NULL)
		{
			fprintf(stderr, "failed to allocate send queue\n");
			exit(1);
		}
	}
	return true;
#else
	std::lock_guard<std::mutex> l(m_mutex);

	if (packets.m_send_cursor == 0) return true;

	if (m_send_cursor + packets.m_send_cursor > m_send_buffer.size())
	{
		dropped_bytes_out.fetch_add(packets.m_send_cursor, std::memory_order_relaxed);
		packets.m_send_cursor = 0;
		return false;
	}

	bytes_out.fetch_add(packets.m_send_cursor, std::memory_order_relaxed);

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
	, m_arp(s)
#ifdef USE_WINPCAP
	, m_queue(pcap_sendqueue_alloc(0x100000))
	, m_pcap(s.m_pcap)
#else
	, m_buf(0x100000)
#endif
{
#ifdef USE_WINPCAP
	if (m_queue == NULL)
	{
		fprintf(stderr, "failed to allocate send queue\n");
		exit(1);
	}
#endif
}

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
		dropped_bytes_out.fetch_add(buf_size, std::memory_order_relaxed);
		return false;
	}

	std::uint8_t* ptr = &m_buf[m_send_cursor];

	std::uint8_t* prefix = ptr;
	ptr += 2;
#endif

#ifdef USE_SYSTEM_SEND_SOCKET
	int len = 0;

	memcpy(ptr, to, sizeof(sockaddr_in));
	ptr += sizeof(sockaddr_in);
	len += sizeof(sockaddr_in);
	for (int i = 0; i < num; ++i)
	{
		memcpy(ptr, v[i].iov_base, v[i].iov_len);
		ptr += v[i].iov_len;
		len += v[i].iov_len;
	}
	m_send_cursor += len + 2;

#else

	if (to->sin_family != AF_INET)
	{
		fprintf(stderr, "unsupported network protocol (only IPv4 is supported)\n");
		return false;
	}

	int len = 0;
	int r;

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
			r = render_eth_frame(ptr, 1500 - len, to, from, &m_mask
				, m_eth_from, m_arp);
			if (r < 0) return false;
			ptr += len;
			len += r;
			break;
		}
		default:
			// unsupported link layer
			fprintf(stderr, "unsupported data link layer (%d)\n", m_link_layer);
			return false;
	}

	r = render_ip_frame(ptr, 1500 - len, v, num, to, from);

	if (r < 0) return false;
	len += r;

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

#endif // USE_SYSTEM_SEND_SOCKET

	return true;
}

#ifdef USE_WINPCAP
void packet_socket::send_thread()
{
	std::vector<pcap_send_queue*> local_buffer;

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
			std::this_thread::sleep_for(
				std::chrono::milliseconds(sleep_timers[sleep-1]));
		}

		{
			std::lock_guard<std::mutex> l(m_mutex);
			if (m_send_buffer.empty())
			{
				if (sleep < sizeof(sleep_timers)/sizeof(sleep_timers[0]))
					++sleep;
				continue;
			}


			local_buffer.swap(m_send_buffer);
		}

		sleep = 0;

		for (auto i : local_buffer)
		{
			int r = pcap_sendqueue_transmit(m_pcap, i, 0);
			if (r < 0)
				fprintf(stderr, "pcap_setfilter() = %d \"%s\"\n", r, pcap_geterr(m_pcap));


			std::lock_guard<std::mutex> l(m_mutex);
			m_free_list.push_back(i);
		}
		local_buffer.clear();
	}

}
#else
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
			std::this_thread::sleep_for(
				std::chrono::milliseconds(sleep_timers[sleep-1]));
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

void packet_socket::local_endpoint(sockaddr_in* addr)
{
	*addr = m_our_addr;
}

