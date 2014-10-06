/*
* KASUMI
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* KASUMI, the block cipher used in 3G telephony
*/
class KASUMI : Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "KASUMI"; }
		BlockCipher clone() const { return new KASUMI; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!ushort EK;
};