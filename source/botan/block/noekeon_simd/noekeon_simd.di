/*
* Noekeon in SIMD
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.noekeon;
/**
* Noekeon implementation using SIMD operations
*/
class Noekeon_SIMD : public Noekeon
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		BlockCipher clone() const { return new Noekeon_SIMD; }
};