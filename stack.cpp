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

#include "stack.hpp"
#include "arp_cache.hpp"
#include <cstdint>

int render_eth_frame(std::uint8_t* buf, int len
	, sockaddr_in const* to
	, sockaddr_in const* from
	, sockaddr_in const* mask
	, address_eth const& eth_from
	, arp_cache const& arp)
{
	int ret = 0;

	if (len < 14) return -1;

	address_eth const& mac = arp.lookup(from, to, mask);

	memcpy(buf, mac.addr, 6);
	// source MAC address
	memcpy(buf + 6, eth_from.addr, 6);
	// ethertype (upper layer protocol)
	// 0x0800 = IPv4
	// 0x86dd = IPv6
	buf[12] = 0x08;
	buf[13] = 0x00;
	buf += 14;
	ret += 14;
	len -= 14;
	return ret;
}

int render_ip_frame(std::uint8_t* buf, int len
	, iovec const* v, int num
	, sockaddr_in const* to
	, sockaddr_in const* from)
{
	int buf_size = 0;
	for (int i = 0; i < num; ++i) buf_size += v[i].iov_len;
	if (len - 20 - 8 < buf_size) return -1;

	int ret = 0;

	// version and header length
	buf[0] = (4 << 4) | 5;
	// DSCP and ECN
	buf[1] = 0;

	// packet length
	buf[2] = (buf_size + 20 + 8) >> 8;
	buf[3] = (buf_size + 20 + 8) & 0xff;

	// identification
	buf[4] = 0;
	buf[5] = 0;

	// fragment offset and flags
	buf[6] = 0;
	buf[7] = 0;

	// TTL
	buf[8] = 0x80;

	// protocol
	buf[9] = 17;

	// checksum
	buf[10] = 0;
	buf[11] = 0;

	// from addr
	memcpy(buf + 12, &from->sin_addr.s_addr, 4);

	// to addr
	memcpy(buf + 16, &to->sin_addr.s_addr, 4);

	// calculate the IP checksum
	std::uint16_t chk = 0;
	for (int i = 0; i < 20; i += 2)
	{
		chk += (buf[i] << 8) | buf[i+1];
	}
	chk = ~chk;

	buf[10] = chk >> 8;
	buf[11] = chk & 0xff;

	buf += 20;
	ret += 20;
	len -= 20;

	if (from->sin_port == 0)
	{
		// we need to make up a source port here if our
		// listen port is 0 (i.e. in "promiscuous" mode)
		// this essentially only happens in the load test
		uint16_t port = htons(6881);
		memcpy(&buf[0], &port, 2);
	}
	else
	{
		memcpy(&buf[0], &from->sin_port, 2);
	}
	memcpy(&buf[2], &to->sin_port, 2);
	buf[4] = (buf_size + 8) >> 8;
	buf[5] = (buf_size + 8) & 0xff;

	// UDP checksum
	buf[6] = 0;
	buf[7] = 0;

	buf += 8;
	ret += 8;
	len -= 8;

	for (int i = 0; i < num; ++i)
	{
		memcpy(buf, v[i].iov_base, v[i].iov_len);
		buf += v[i].iov_len;
		ret += v[i].iov_len;
		len -= v[i].iov_len;
	}

	return ret;
}
