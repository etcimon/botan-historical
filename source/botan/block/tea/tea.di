/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block.block_cipher;
/**
* TEA
*/
class TEA : Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "TEA"; }
		BlockCipher clone() const { return new TEA; }
	private:
		void key_schedule(in ubyte*, size_t);
		secure_vector!uint K;
};