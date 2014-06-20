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


#ifndef SOCKET_SYSTEM_HPP
#define SOCKET_SYSTEM_HPP

#include <array>

struct packet_buffer;

struct packet_socket
{
	friend struct packet_buffer;

	packet_socket(int listen_port, bool receive = false);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(packet_buffer& packets);

	// fills in the in_packets array with incoming packets. Returns the number filled in
	int receive(incoming_packet_t* in_packets, int num);
private:
	int m_socket;
	// this buffer needs to be aligned, because we
	// overlay structs to parse out packets
	std::array<uint64_t, 1500/8> m_buffer;
	bool m_receive;
};

struct packet_buffer
{
	friend struct packet_socket;

	explicit packet_buffer(packet_socket& s)
		: m_socket(s.m_socket)
	{}

	bool append(iovec const* v, int num, sockaddr_in const* to);

private:
	int m_socket;
};

#endif // SOCKET_SYSTEM_HPP

