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

#include <pcap/pcap.h>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

enum {
	// the receive buffer size for packets, specified in uint64_ts
	receive_buffer_size = 0x40000,

	// specified in bytes
	send_buffer_size = 0x800000,
};

struct packet_buffer;

struct address_eth
{ uint8_t addr[6]; };

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

	void send_thread();

	pcap_t* m_pcap;
	int m_link_layer;
	std::atomic<uint32_t> m_closed;
	std::array<uint64_t, receive_buffer_size> m_buffer;

	sockaddr_in m_our_addr;
	address_eth m_eth_addr;

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
};

// TODO: WinPcap has a much more efficient bulk-sending API which would be
// nice to use
struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s)
		: m_link_layer(s.m_link_layer)
		, m_send_cursor(0)
		, m_from(s.m_our_addr)
		, m_eth_from(s.m_eth_addr)
		, m_buf(0x100000)
	{}

	bool append(iovec const* v, int num, sockaddr_in const* to);

	bool append_impl(iovec const* v, int num, sockaddr_in const* to
		, sockaddr_in const* from);

private:
	int m_link_layer;
	int m_send_cursor;
	sockaddr_in m_from;
	address_eth m_eth_from;
	std::vector<uint8_t> m_buf;
};

