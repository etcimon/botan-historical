/*
* Threefish-512 in AVX2
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.threefish;
/**
* Threefish-512
*/
class Threefish_512_AVX2 : Threefish_512
{
	private:
		override void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		override void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		override BlockCipher clone() const { return new Threefish_512_AVX2; }
};