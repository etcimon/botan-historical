/*
* Auto Seeded RNG
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.rng;
import string;
class AutoSeeded_RNG : public RandomNumberGenerator
{
	public:
		void randomize(ubyte* output, size_t len)
		{ m_rng.randomize(output, len); }

		bool is_seeded() const { return m_rng.is_seeded(); }

		void clear() { m_rng.clear(); }

		string name() const { return m_rng.name(); }

		void reseed(size_t poll_bits = 256) { m_rng.reseed(poll_bits); }

		void add_entropy(in ubyte* input, size_t len)
		{ m_rng.add_entropy(input, len); }

		AutoSeeded_RNG() : m_rng(RandomNumberGenerator::make_rng()) {}
	private:
		Unique!RandomNumberGenerator m_rng;
};