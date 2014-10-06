/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
import botan.hash;
/**
* EMSA1 from IEEE 1363
* Essentially, sign the hash directly
*/
class EMSA1 : EMSA
{
	public:
		/**
		* @param hash the hash function to use
		*/
		EMSA1(HashFunction hash) : m_hash(hash) {}

	package:
		size_t hash_output_length() const { return m_hash.output_length(); }
	private:
		void update(const ubyte[], size_t);
		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte msg,
												  size_t output_bits,
												  RandomNumberGenerator rng);

		bool verify(in SafeVector!ubyte coded,
						in SafeVector!ubyte raw,
						size_t key_bits);

		Unique!HashFunction m_hash;
};