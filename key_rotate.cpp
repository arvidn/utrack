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

#include <random>
#include "key_rotate.hpp"

using std::chrono::steady_clock;
using std::chrono::hours;

key_rotate::key_rotate()
	: m_current(ATOMIC_VAR_INIT(0))
	, m_last_rotate(steady_clock::now())
{
	std::random_device dev;
	std::generate(m_secrets[0].key.begin(), m_secrets[0].key.end(), std::ref(dev));
	std::generate(m_secrets[1].key.begin(), m_secrets[1].key.end(), std::ref(dev));
}

void key_rotate::tick()
{
	steady_clock::time_point now = steady_clock::now();
	if (now < m_last_rotate + hours(6)) return;

	std::uint32_t next_cur = (m_current.load() + 1 ) % 3;

	std::random_device dev;
	std::generate(m_secrets[next_cur].key.begin()
		, m_secrets[next_cur].key.end()
		, std::ref(dev));
	m_current = next_cur;
}

std::array<std::uint8_t, 16> const& key_rotate::cur_key() const
{
	return m_secrets[m_current.load()].key;
}

std::array<std::uint8_t, 16> const& key_rotate::prev_key() const
{
	return m_secrets[(m_current.load() - 1) % 3].key;
}

