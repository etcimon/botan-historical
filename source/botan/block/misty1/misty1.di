/*
* MISTY1
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* MISTY1
*/
class MISTY1 : public Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "MISTY1"; }
		BlockCipher* clone() const { return new MISTY1; }

		/**
		* @param rounds the number of rounds. Must be 8 with the current
		* implementation
		*/
		MISTY1(size_t rounds = 8);
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!ushort EK, DK;
};