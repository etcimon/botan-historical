/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
import botan.hash.hash;
/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR : EMSA
{
	public:

		/**
		* @param hash the hash object to use
		*/
		PSSR(HashFunction hash);

		/**
		* @param hash the hash object to use
		* @param salt_size the size of the salt to use in bytes
		*/
		PSSR(HashFunction hash, size_t salt_size);
	private:
		void update(in ubyte* input, size_t length);

		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte msg,
												  size_t output_bits,
												  RandomNumberGenerator rng);

		bool verify(in SafeVector!ubyte coded,
						in SafeVector!ubyte raw,
						size_t key_bits);

		size_t SALT_SIZE;
		Unique!HashFunction hash;
};