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

		nm_dispatch(m_hw_rings, m_sw_rings, num, callback);

		// the callback here is always ignoring the packets, because we're not
		// interested in intercepting packets being sent by the operating system,
		// they are just all forwarded to the hardware rings
		nm_dispatch(m_sw_rings, m_hw_rings, num
			, [](uint8_t* buf, int len) { return false; });

#error transmit and receive on both hw and sw rings (signal the kernel)

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
		int c;
		int got = 0;
		int ri = src->cur_rx_ring;
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
		for (c=0; c < n && cnt != got; c++) {
			ri = src->cur_rx_ring + c;
			if (ri > src->last_rx_ring)
				ri = src->first_rx_ring;
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

struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s);
	~packet_buffer();

	bool append(iovec const* v, int num, sockaddr_in const* to);

	bool append_impl(iovec const* v, int num, sockaddr_in const* to
		, sockaddr_in const* from);

private:

	int m_link_layer;

	sockaddr_in m_from;
	sockaddr_in m_mask;
	address_eth m_eth_from;

	arp_cache const& m_arp;
};

#endif // SOCKET_NETMAP_HPP

