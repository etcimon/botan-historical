/*
* X9.31 EMSA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
import botan.hash;
/**
* EMSA from X9.31 (EMSA2 in IEEE 1363)
* Useful for Rabin-Williams, also sometimes used with RSA in
* odd protocols.
*/
class EMSA_X931 : public EMSA
{
	public:
		/**
		* @param hash the hash object to use
		*/
		EMSA_X931(HashFunction hash);
	private:
		void update(const ubyte[], size_t);
		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte, size_t,
												 RandomNumberGenerator rng);

		bool verify(in SafeVector!ubyte, in SafeVector!ubyte,
						size_t);

		SafeVector!ubyte m_empty_hash;
		Unique!HashFunction m_hash;
		ubyte m_hash_id;
};