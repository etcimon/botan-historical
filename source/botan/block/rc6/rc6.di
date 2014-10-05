/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* RC6, Ron Rivest's AES candidate
*/
class RC6 : public Block_Cipher_Fixed_Params!(16, 1, 32)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "RC6"; }
		BlockCipher clone() const { return new RC6; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint S;
};