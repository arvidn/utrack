/*
utrack is a very small an efficient BitTorrent tracker
Copyright (C) 2014  Arvid Norberg

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

#ifndef _CONFIG_HPP_
#define _CONFIG_HPP_

// magic constants

enum
{
	// the max number of peers we'll keep in a peerlist for a single
	// torrent.
	max_peerlist_size = 300000,

	// the default number of peers to return, unless a smaller number
	// was specified in the request
	default_num_want = 200,

	// the number of seconds between announces (seconds)
	default_interval = 1800,

	// if this is true, we allow peers to set which IP
	// they will announce as. This is off by default since
	// it allows for spoofing
#ifdef _DEBUG
	allow_alternate_ip = 1,
#else
	allow_alternate_ip = 0,
#endif

	socket_buffer_size = 5 * 1024 * 1024,

	// the number of times to read (without receiving any data) from the udp
	// socket before going to sleep
	receive_spin_count = 10
};

#endif

