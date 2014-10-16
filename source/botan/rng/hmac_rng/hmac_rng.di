/*
* HMAC RNG
* (C) 2008,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mac.mac;
import botan.rng;
import vector;
/**
* HMAC_RNG - based on the design described in "On Extract-then-Expand
* Key Derivation Functions and an HMAC-based KDF" by Hugo Krawczyk
* (henceforce, 'E-t-E')
*
* However it actually can be parameterized with any two MAC functions,
* not restricted to HMAC (this variation is also described in
* Krawczyk's paper), for instance one could use HMAC(SHA-512) as the
* extractor and CMAC(AES-256) as the PRF.
*/
class HMAC_RNG : RandomNumberGenerator
{
	public:
		void randomize(ubyte buf[], size_t len);
		bool is_seeded() const;
		void clear();
		string name() const;

		void reseed(size_t poll_bits);
		void add_entropy(const ubyte[], size_t);

		/**
		* @param extractor a MAC used for extracting the entropy
		* @param prf a MAC used as a PRF using HKDF construction
		*/
		HMAC_RNG(MessageAuthenticationCode extractor,
					MessageAuthenticationCode prf);
	private:
		Unique!MessageAuthenticationCode m_extractor;
		Unique!MessageAuthenticationCode m_prf;

		size_t m_collected_entropy_estimate = 0;
		size_t m_output_since_reseed = 0;

		SafeVector!ubyte m_K;
		uint m_counter = 0;
};