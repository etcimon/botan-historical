/*
* HMAC_DRBG (SP800-90A)
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.rng;
import botan.mac;
/**
* HMAC_DRBG (SP800-90A)
*/
class HMAC_DRBG : public RandomNumberGenerator
{
	public:
		void randomize(byte buf[], size_t buf_len);
		bool is_seeded() const;
		void clear();
		string name() const;

		void reseed(size_t poll_bits);

		void add_entropy(in byte* input, size_t input_len);

		/**
		* @param mac the underlying mac function (eg HMAC(SHA-512))
		* @param underlying_rng RNG used generating inputs (eg HMAC_RNG)
		*/
		HMAC_DRBG(MessageAuthenticationCode* mac,
					 RandomNumberGenerator* underlying_rng);

	private:
		void update(in byte* input, size_t input_len);

		Unique!MessageAuthenticationCode m_mac;
		Unique!RandomNumberGenerator m_prng;

		SafeVector!byte m_V;
		size_t m_reseed_counter;
};