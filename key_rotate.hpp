/*
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

#include <chrono>
#include <array>
#include <atomic>
#include <cstdint>

struct key_rotate
{
	key_rotate();

	// tick must only be called from a single thread!
	void tick();

	// these may be called by any thread
	std::array<std::uint8_t, 16> const& cur_key() const;
	std::array<std::uint8_t, 16> const& prev_key() const;

private:

	struct secret_key_t
	{
		std::array<std::uint8_t, 16> key;
		// place all keys in separate cache lines so that
		// writing a new one doesn't evict the ones the other
		// threads are reading
		uint8_t padding[64-16];
	};
	// these are the rotating secret keys. There are 3 keys so that we
	// can generate a new one in the 3:rd slot without being worried about
	// it being used by any other thread. The most recent secret is
	// secrets[current_secret], and the previous secret is
	// every few hours or so, the secret is rotated. To rotate the cache,
	// the unused secrets entry is initialized with random bytes then the
	// current_secret is incremented (and wrapped at 3).
	// secrets[(current_secrets - 1)%3]

	secret_key_t m_secrets[3];
	std::atomic<std::uint32_t> m_current;
	std::chrono::steady_clock::time_point m_last_rotate;
};

