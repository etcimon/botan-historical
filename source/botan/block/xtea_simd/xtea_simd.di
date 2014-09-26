/*
* XTEA in SIMD
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/xtea.h>
/**
* XTEA implemented using SIMD operations
*/
class XTEA_SIMD : public XTEA
{
	public:
		size_t parallelism() const { return 8; }

		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;
		BlockCipher* clone() const { return new XTEA_SIMD; }
};