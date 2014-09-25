/*
* Serpent (SIMD)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/serpent.h>
/**
* Serpent implementation using SIMD
*/
class Serpent_SIMD : public Serpent
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		BlockCipher* clone() const { return new Serpent_SIMD; }
};