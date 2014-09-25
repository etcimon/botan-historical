/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/rng.h>
#include <botan/block_cipher.h>
/**
* ANSI X9.31 RNG
*/
class ANSI_X931_RNG : public RandomNumberGenerator
{
	public:
		void randomize(byte[], size_t);
		bool is_seeded() const;
		void clear();
		string name() const;

		void reseed(size_t poll_bits);
		void add_entropy(const byte[], size_t);

		/**
		* @param cipher the block cipher to use in this PRNG
		* @param rng the underlying PRNG for generating inputs
		* (eg, an HMAC_RNG)
		*/
		ANSI_X931_RNG(BlockCipher* cipher,
						  RandomNumberGenerator* rng);

	private:
		void rekey();
		void update_buffer();

		std::unique_ptr<BlockCipher> m_cipher;
		std::unique_ptr<RandomNumberGenerator> m_prng;
		SafeArray!byte m_V, m_R;
		size_t m_R_pos;
};