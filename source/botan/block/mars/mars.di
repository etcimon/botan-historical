/*
* MARS
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* MARS, IBM's candidate for AES
*/
class MARS : public Block_Cipher_Fixed_Params<16, 16, 32, 4>
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "MARS"; }
		BlockCipher* clone() const { return new MARS; }
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!uint EK;
};