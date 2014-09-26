/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/emsa.h>
#include <botan/hash.h>
/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR : public EMSA
{
	public:

		/**
		* @param hash the hash object to use
		*/
		PSSR(HashFunction* hash);

		/**
		* @param hash the hash object to use
		* @param salt_size the size of the salt to use in bytes
		*/
		PSSR(HashFunction* hash, size_t salt_size);
	private:
		void update(in byte* input, size_t length);

		SafeVector!byte raw_data();

		SafeVector!byte encoding_of(in SafeVector!byte msg,
												  size_t output_bits,
												  RandomNumberGenerator& rng);

		bool verify(in SafeVector!byte coded,
						in SafeVector!byte raw,
						size_t key_bits);

		size_t SALT_SIZE;
		std::unique_ptr<HashFunction> hash;
};