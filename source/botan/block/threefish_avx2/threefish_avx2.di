/*
* Threefish-512 in AVX2
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/threefish.h>
/**
* Threefish-512
*/
class Threefish_512_AVX2 : public Threefish_512
{
	private:
		void encrypt_n(byte* input, byte* output, size_t blocks) const override;
		void decrypt_n(byte* input, byte* output, size_t blocks) const override;
		BlockCipher* clone() const override { return new Threefish_512_AVX2; }
};