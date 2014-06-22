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

enum {
	// the receive buffer size for packets, specified in uint64_ts
	receive_buffer_size = 0x40000,

	// specified in bytes
	send_buffer_size = 0x800000,
};

struct packet_buffer;

struct address_eth
{
	address_eth() { memset(addr, 0, sizeof(addr)); }
	explicit address_eth(uint8_t const* ptr) { memcpy(addr, ptr, sizeof(addr)); }
	uint8_t addr[6];
};

struct packet_socket
{
	friend struct packet_buffer;

	// a listen port of 0 means accept packets on any port
	explicit packet_socket(char const* device, int listen_port);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(packet_buffer& packets);

	// fills in the in_packets array with incoming packets. Returns the number filled in
	int receive(incoming_packet_t* in_packets, int num);

private:

	pcap_t* m_pcap;
	int m_link_layer;
	std::atomic<uint32_t> m_closed;
	std::array<uint64_t, receive_buffer_size> m_buffer;

	// the IP and port we send packets from
	sockaddr_in m_our_addr;

	// the network mask for this interface. This is used to maintain the 
	// ARP cache
	sockaddr_in m_mask;

	// the ethernet address for this interface. Use for rendering ethernet
	// frames for outgoing packets.
	address_eth m_eth_addr;

	// maps local IPs (IPs masked by the network mask)
	// to the corresponding ethernet address (MAC address)
	std::unordered_map<uint32_t, address_eth> m_arp_cache;

#ifndef USE_WINPCAP
	void send_thread();

	// this mutex just protects the send buffer
	std::mutex m_mutex;

	// this contains all packets we want to send as one contiguous array. Each
	// packet has a 2 byte, host order length prefix, followed by that many
	// bytes of payload. This is double buffered. Other threads write to one
	// buffer while the sending thread reads from the other. This lowers the
	// lock contention while sending
	std::vector<uint8_t> m_send_buffer;

	// the cursor of where new outgoing packets should be written in the
	// send buffer
	int m_send_cursor;

	// the thread that's used to send the packets put in the send queue
	std::vector<std::thread> m_send_threads;
#endif
};

// TODO: WinPcap has a much more efficient bulk-sending API which would be
// nice to use
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
#ifndef USE_WINPCAP
	int m_send_cursor;
#endif
	sockaddr_in m_from;
	sockaddr_in m_mask;
	address_eth m_eth_from;
	std::unordered_map<uint32_t, address_eth>& m_arp_cache;
#ifdef USE_WINPCAP
	pcap_send_queue* m_queue;
	pcap_t* m_pcap;
#else
	std::vector<uint8_t> m_buf;
#endif
};

#endif // SOCKET_PCAP_HPP

