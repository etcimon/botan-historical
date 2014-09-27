/*
* CAST-256
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* CAST-256
*/
class CAST_256 : public Block_Cipher_Fixed_Params!(16, 4, 32, 4)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "CAST-256"; }
		BlockCipher* clone() const { return new CAST_256; }
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!uint MK;
		SafeVector!byte RK;
};