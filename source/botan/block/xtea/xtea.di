/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* XTEA
*/
class XTEA : Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "XTEA"; }
		BlockCipher clone() const { return new XTEA; }
	package:
		/**
		* @return const reference to the key schedule
		*/
		const secure_vector!uint& get_EK() const { return EK; }

	private:
		void key_schedule(in ubyte*, size_t);
		secure_vector!uint EK;
};