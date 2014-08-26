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

#ifndef SOCKET_PCAP_HPP
#define SOCKET_PCAP_HPP

#include <pcap/pcap.h>

#ifdef USE_WINPCAP
#include <win32-extensions.h>
#endif

#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <unordered_map>

#include "utils.hpp"
#include "arp_cache.hpp"

enum {
	// the receive buffer size for packets, specified in uint64_ts
	receive_buffer_size = 0x40000,

	// specified in bytes
	send_buffer_size = 0x800000,
};

struct packet_buffer;

struct packet_socket : arp_cache
{
	friend struct packet_buffer;

	// a listen port of 0 means accept packets on any port
	explicit packet_socket(sockaddr const* bind_addr);
	explicit packet_socket(char const* device);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(packet_buffer& packets);

	void local_endpoint(sockaddr_in* addr);

private:

	template <class F>
	struct receive_state
	{
		pcap_t* handle;

		// the number of bytes to skip in each buffer to get to the IP
		// header.
		int link_header_size;

		// the number of packets left to receive
		int* num;

		// ignore packets sent to other addresses and ports than this one.
		// a port of 0 means accept packets on any port
		sockaddr_in local_addr;
		sockaddr_in local_mask;

		arp_cache* arp;
		F* callback;
	};

public:

	// receive at least one packet on the socket. No more than num (defaults
	// to 1000). For each received packet, callback is called with the following
	// arguments: (sockaddr_in* from, uint8_t* buffer, int len)
	// the buffer is valid until the callback returns
	// returns -1 on error
	template <class F>
	int receive(F callback, int num = 1000)
	{
		if (num <= 0) return 0;

		// TODO: should we just pass in "this" instead? and make it a member
		// function?
		receive_state<F> st;
		st.handle = m_pcap;
		st.local_addr = m_our_addr;
		st.local_mask = m_mask;
		st.arp = this;
		st.callback = &callback;
		st.num = &num;

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

			r = pcap_dispatch(m_pcap, num, &packet_handler<F>, (uint8_t*)&st);

			if (r == -1)
			{
				fprintf(stderr, "pcap_dispatch() = %d \"%s\"\n", r, pcap_geterr(m_pcap));
				if (r == -3) exit(2);
				return -1;
			}

			if (num <= 0) return 0;

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

private:

	template <class F>
	static void packet_handler(u_char* user, const struct pcap_pkthdr* h
		, const u_char* bytes)
	{
		receive_state<F>* st = (receive_state<F>*)user;

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

		// copy from IP header
		sockaddr_in from;
		memset(&from, 0, sizeof(from));
#if !defined _WIN32 && !defined __linux__
		from.sin_len = sizeof(sockaddr_in);
#endif
		from.sin_family = AF_INET;

		// UDP header: src-port, dst-port, len, chksum
		memcpy(&from.sin_port, udp_header, 2);
		memcpy(&from.sin_addr, ip_header + 12, 4);

		// ETHERNET
		if (st->link_header_size == 14)
		{
			if (st->arp->has_entry(&st->local_addr, &from, &st->local_mask) == 0)
			{
				st->arp->add_arp_entry(&from, address_eth(ethernet_header + 6));
			}
		}

		(*st->callback)(&from, payload, payload_len);

		--*st->num;
	}

	void init(char const* device);

	pcap_t* m_pcap;
	int m_link_layer;
	std::atomic<uint32_t> m_closed;

	// the IP and port we send packets from
	sockaddr_in m_our_addr;

	// the network mask for this interface. This is used to maintain the 
	// ARP cache
	sockaddr_in m_mask;

	// the ethernet address for this interface. Use for rendering ethernet
	// frames for outgoing packets.
	address_eth m_eth_addr;

	void send_thread();

	// this mutex just protects the send buffer
	std::mutex m_mutex;

	// the thread that's used to send the packets put in the send queue
	std::vector<std::thread> m_send_threads;

#ifdef USE_WINPCAP

	std::vector<pcap_send_queue*> m_send_buffer;
	std::vector<pcap_send_queue*> m_free_list;

#else

	// this contains all packets we want to send as one contiguous array. Each
	// packet has a 2 byte, host order length prefix, followed by that many
	// bytes of payload. This is double buffered. Other threads write to one
	// buffer while the sending thread reads from the other. This lowers the
	// lock contention while sending
	std::vector<uint8_t> m_send_buffer;

	// the cursor of where new outgoing packets should be written in the
	// send buffer
	int m_send_cursor;

#endif
};

struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s);
	~packet_buffer();

	bool append(iovec const* v, int num, sockaddr_in const* to);

	bool append_impl(iovec const* v, int num, sockaddr_in const* to
		, sockaddr_in const* from);

	bool is_full(int buf_size) const
	{ return m_send_cursor + buf_size + 28 + 30 > m_buf.size(); }

private:
	int m_link_layer;
#ifndef USE_WINPCAP
	int m_send_cursor;
#endif
	sockaddr_in m_from;
	sockaddr_in m_mask;
	address_eth m_eth_from;
	arp_cache const& m_arp;
#ifdef USE_WINPCAP
	pcap_send_queue* m_queue;
	pcap_t* m_pcap;
#else
	std::vector<uint8_t> m_buf;
#endif
};

#endif // SOCKET_PCAP_HPP

