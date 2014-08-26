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

#ifndef SOCKET_NETMAP_HPP
#define SOCKET_NETMAP_HPP

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

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

	// receive at least one packet on the socket. No more than num (defaults
	// to 1000). For each received packet, callback is called with the following
	// arguments: (sockaddr_in* from, uint8_t* buffer, int len)
	// the buffer is valid until the callback returns
	// returns -1 on error
	template <class F>
	int receive(F callback, int num = 1000)
	{
		if (num <= 0) return 0;

		ioctl(m_hw_rings->fd, NIOCRXSYNC, NULL);
		ioctl(m_sw_rings->fd, NIOCRXSYNC, NULL);

		nm_dispatch(m_hw_rings, m_sw_rings, num, [&](uint8_t* buf, int len) -> bool
		{
			// TODO: support IPv6 also

			uint8_t const* ethernet_header = buf;

			// assume ethernet for now
			const int link_header_size = 14;

			uint8_t const* ip_header = buf + link_header_size;

			// we only support IPv4 for now, and no IP options, just
			// the 20 byte header
   
			// version and length. Ignore any non IPv4 packets and any packets
			// with IP options headers
			if (ip_header[0] != 0x45) {
				// this is noisy, don't print out for every IPv6 packet
				//		fprintf(stderr, "ignoring IP packet version: %d header size: %d\n"
				//			, ip_header[0] >> 4, (ip_header[0] & 0xf) * 4);
				return false;
			}
   
			// flags (ignore any packet with more-fragments set)
			if (ip_header[6] & 0x20) {
				fprintf(stderr, "ignoring fragmented IP packet\n");
				return false;
			}
   
			// ignore any packet with fragment offset
			if ((ip_header[6] & 0x1f) != 0 || ip_header[7] != 0) {
				fprintf(stderr, "ignoring fragmented IP packet\n");
				return false;
			}
   
			// ignore any packet whose transport protocol is not UDP
			if (ip_header[9] != 0x11) {
				fprintf(stderr, "ignoring non UDP packet (protocol: %d)\n"
					, ip_header[9]);
				return false;
			}
   
			uint8_t const* udp_header = ip_header + 20;
   
			// only look at packets to our listen port
			if (m_our_addr.sin_port != 0 &&
				memcmp(&udp_header[2], &m_our_addr.sin_port, 2) != 0)
			{
				fprintf(stderr, "ignoring packet not to our port (port: %d)\n"
					, ntohs(*(uint16_t*)(udp_header+2)));
				return false;
			}
   
			// only look at packets sent to the IP we bound to
			// port 0 means any address
			if (m_our_addr.sin_port != 0 &&
				memcmp(&m_our_addr.sin_addr.s_addr, ip_header + 16, 4) != 0)
			{
				return false;
			}
   
			int payload_len = len - 28 - link_header_size;
			uint8_t const* payload = buf + 28 + link_header_size;

			if (payload_len > 1500)
			{
				fprintf(stderr, "incoming packet too large\n");
				return false;
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
			if (has_entry(&m_our_addr, &from, &m_mask) == 0)
				add_arp_entry(&from, address_eth(ethernet_header + 6));

			callback(&from, payload, payload_len);

			return true;
		});

		// the callback here is always ignoring the packets, because we're not
		// interested in intercepting packets being sent by the operating system,
		// they are just all forwarded to the hardware rings
		nm_dispatch(m_sw_rings, m_hw_rings, num
			, [](uint8_t* buf, int len) { return false; });

		// commit the packets we moved over to the sw ring
		ioctl(m_sw_rings->fd, NIOCTXSYNC, NULL);

		// commit all the responses we generated as well as
		// the outgoing packets we forwarded
		ioctl(m_hw_rings->fd, NIOCTXSYNC, NULL);

		return 0;
	}

private:

	// this is a template to avoid the cost of function pointer indirection
	// and possible instruction pre-fetch stall. packets are pulled from src,
	// and forwarded to dst (except for the ones accepted by the callback)
	// the callback has this callback: bool(uint8_t* buf, int len). The buffer
	// is the raw packet, including the ethernet frame. If the function returns
	// true, it means the packet was handled (i.e. it was addressed to the user).
	// if the callback returns false, the packet will be forwarded to the
	// operating system.
	template <class F>
	int nm_dispatch(nm_desc* src, nm_desc* dst, int cnt, F cb)
	{
		int n = src->last_rx_ring - src->first_rx_ring + 1;
		int got = 0;

		// this is the transmit ring index
		int ti = dst->cur_tx_ring;

		ti = dst->cur_tx_ring;
		if (ti > dst->last_tx_ring)
			ti = dst->first_tx_ring;
		netmap_ring* tx_ring = NETMAP_TXRING(dst->nifp, ti);

		// the the both descriptors share the memory space, we can
		// transfer packets between them simply by changing buffer references
		bool supports_zerocopy = src->mem == dst->mem;

		// cnt == -1 means infinite, but rings have a finite amount
		// of buffers and the int is large enough that we never wrap,
		// so we can omit checking for -1

		// ri is the index of the receive ring we're reading from.
		// when a ring is depleted, we move on to the next ring
		int ri;
		for (ri = src->cur_rx_ring; ri <= src->last_rx_ring
			&& cnt != got; ++ri) {

			assert(ri <= src->last_rx_ring);
			netmap_ring* rx_ring = NETMAP_RXRING(src->nifp, ri);

			for ( ; !nm_ring_empty(rx_ring) && cnt != got; got++) {
				u_int i = rx_ring->cur;
				netmap_slot& rs = rx_ring->slot[i];
				u_char *buf = (u_char *)NETMAP_BUF(rx_ring, rs.buf_idx);

				// __builtin_prefetch(buf);
				bool handled = cb(buf, rs.len);
				if (!handled)
				{
					// move this buffer over to the dst ring
					netmap_slot& ts = tx_ring->slot[tx_ring->cur];
					ts.len = rs.len;

					// copy from rx_ring to tx_ring
					if (supports_zerocopy) {
						std::swap(ts.buf_idx, rs.buf_idx);
						ts.flags |= NS_BUF_CHANGED;
						rs.flags |= NS_BUF_CHANGED;
					} else {
						assert(false);
					}

					assert(!nm_ring_empty(tx_ring));
					tx_ring->cur = nm_ring_next(tx_ring, tx_ring->cur);

					if (nm_ring_empty(tx_ring)) {
						++ti;

						if (ti > dst->last_tx_ring)
							ti = dst->first_tx_ring;
						tx_ring = NETMAP_TXRING(dst->nifp, ti);
					}
				}
				rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, i);
			}
		}
		src->cur_rx_ring = ri;
		return got;
	}

	void init(char const* device);

	// the hardware rings of the NIC
	nm_desc *m_hw_rings;

	// the software stack rings
	nm_desc *m_sw_rings;

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
};

#error it probably doesn't make sense to have a separate type for this \
	a socket that wants to buffer outgoing packets can just do that internally
struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s);
	~packet_buffer();

	bool append(iovec const* v, int num, sockaddr_in const* to);

	bool append_impl(iovec const* v, int num, sockaddr_in const* to
		, sockaddr_in const* from);

	bool is_full(int buf_size) const;

private:

	int m_link_layer;

	sockaddr_in m_from;
	sockaddr_in m_mask;
	address_eth m_eth_from;

	arp_cache const& m_arp;
};

#endif // SOCKET_NETMAP_HPP

