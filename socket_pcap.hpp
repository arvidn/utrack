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

enum {
	// the receive buffer size for packets, specified in uint64_ts
	receive_buffer_size = 16384,

	// specified in bytes
	send_buffer_size = 0x400000,
};

struct packet_buffer;

struct packet_socket
{
	friend struct packet_buffer;

	explicit packet_socket(bool receive = false);
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

	// this mutex just protects the send buffer
	std::mutex m_mutex;

	// this contains all packets we want to send as one contiguous array. Each
	// packet has a 2 byte, host order length prefix, followed by that many
	// bytes of payload. This is double buffered. Other threads write to one
	// buffer while the sending thread reads from the other. This lowers the
	// lock contention while sending
	std::vector<uint8_t> m_send_buffer[2];

	// the cursor of where new outgoing packets should be written in the
	// send buffer
	int m_send_cursor;

	// the index of the send buffer to use for writing new outgoing packets.
	// the other buffer is used internally by the thread that's actually
	// sending the packets
	int m_buffer_idx;

	// the thread that's used to send the packets put in the send queue
	std::thread m_send_thread;
};

struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s)
		: m_link_layer(s.m_link_layer)
		, m_send_cursor(0)
		, m_buf(0x100000)
	{}

	bool append(iovec const* v, int num, sockaddr const* to, socklen_t tolen);

private:
	int m_link_layer;
	int m_send_cursor;
	std::vector<uint8_t> m_buf;
};

