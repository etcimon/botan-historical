/*
* Serpent (SIMD)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_SERPENT_SIMD_H__

#include <botan/serpent.h>
/**
* Serpent implementation using SIMD
*/
class Serpent_SIMD : public Serpent
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		BlockCipher* clone() const { return new Serpent_SIMD; }
};