/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2011  Arvid Norberg

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

#ifndef _ENDIAN_HPP_
#define _ENDIAN_HPP_

#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be64toh(x) betoh64(x)
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
uint64_t inline be64toh(uint64_t x)
{
	uint64_t ret;
	uint8_t* d = ((uint8_t*)&ret) + 7;
	uint8_t* s = (uint8_t*)&x;
	
	for (int i = 0; i < sizeof(x); ++i, --d, ++s)
		*d = *s;
	return ret;
}
#else
#define be64toh(x) x
#endif
#endif

#endif // _ENDIAN_HPP_

