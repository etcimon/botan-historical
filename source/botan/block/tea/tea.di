/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* TEA
*/
class TEA : public Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "TEA"; }
		BlockCipher clone() const { return new TEA; }
	private:
		void key_schedule(in byte*, size_t);
		secure_vector!uint K;
};