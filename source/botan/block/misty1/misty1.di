/*
* MISTY1
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* MISTY1
*/
class MISTY1 : public Block_Cipher_Fixed_Params<8, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "MISTY1"; }
		BlockCipher* clone() const { return new MISTY1; }

		/**
		* @param rounds the number of rounds. Must be 8 with the current
		* implementation
		*/
		MISTY1(size_t rounds = 8);
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u16bit> EK, DK;
};