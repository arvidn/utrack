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

#ifndef _PACKET_SOCKET_HPP_
#define _PACKET_SOCKET_HPP_

#include <cstdint>
#include <atomic>
#include <vector>
#include <array>
#include <mutex>

#ifdef _WIN32

#include <winsock2.h>

// windows doesn't have iovec or socklen
struct iovec {
	void* iov_base;
	int iov_len;
};

typedef int socklen_t;

#else

#include <netinet/in.h> // for sockaddr
#include <sys/socket.h> // for iovec

#endif

struct incoming_packet_t
{
	sockaddr_storage from;
	char* buffer;
	int buflen;
};

#ifdef USE_PCAP
#include "socket_pcap.hpp"
#else
#include "socket_system.hpp"
#endif

#endif // _PACKET_SOCKET_HPP_

