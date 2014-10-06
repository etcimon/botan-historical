/*
* Serpent (SIMD)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.serpent;
/**
* Serpent implementation using SIMD
*/
class Serpent_SIMD : Serpent
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		BlockCipher clone() const { return new Serpent_SIMD; }
};