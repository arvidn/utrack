/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2013  Arvid Norberg

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

#ifndef _PACKET_SOCKET_HPP_
#define _PACKET_SOCKET_HPP_

#include <cstdint>
#include <netinet/in.h>

struct incoming_packet_t
{
	sockaddr_storage from;
	socklen_t fromlen;
	char* buffer;
	int buflen;
};

struct packet_socket
{
	packet_socket(bool receive = false);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(iovec const* v, int num, sockaddr const* to, socklen_t tolen);

	// fills in the in_packets array with incoming packets. Returns the number filled in
	int receive(incoming_packet_t* in_packets, int num);
private:
	int m_socket;
	// this buffer is aligned
	uint64_t m_buffer[1500/8];
	bool m_receive;
};

#endif // _PACKET_SOCKET_HPP_

