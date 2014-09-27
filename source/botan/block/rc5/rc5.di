/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* RC5
*/
class RC5 : public Block_Cipher_Fixed_Params!(8, 1, 32)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const;
		BlockCipher* clone() const { return new RC5(rounds); }

		/**
		* @param rounds the number of RC5 rounds to run. Must be between
		* 8 and 32 and a multiple of 4.
		*/
		RC5(size_t rounds);
	private:
		void key_schedule(in byte*, size_t);

		size_t rounds;
		secure_vector!uint S;
};