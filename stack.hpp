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

#include "utils.hpp" // for address_eth
#include <cstdint>

struct sockaddr_in;
struct arp_cache;

// renders an ethernet frame into the buffer 'buf', which can hold 'len'
// bytes. The number of bytes written to the buffer is returned, or -1 if
// somehting failed.
int render_eth_frame(std::uint8_t* buf, int len
	, sockaddr_in const* to
	, sockaddr_in const* from
	, sockaddr_in const* mask
	, address_eth const& eth_from
	, arp_cache const& arp);

// renders an IP and UDP frame into the buffer 'buf' which can hold 'len'
// bytes. The number of bytes written to the buffer is returned, or -1 if
// somehting failed.
int render_ip_frame(std::uint8_t* buf, int len
	, iovec const* v, int num
	, sockaddr_in const* to
	, sockaddr_in const* from);

