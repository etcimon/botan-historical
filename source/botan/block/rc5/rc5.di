/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* RC5
*/
class RC5 : public Block_Cipher_Fixed_Params<8, 1, 32>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const;
		BlockCipher* clone() const { return new RC5(rounds); }

		/**
		* @param rounds the number of RC5 rounds to run. Must be between
		* 8 and 32 and a multiple of 4.
		*/
		RC5(size_t rounds);
	private:
		void key_schedule(const byte[], size_t);

		size_t rounds;
		secure_vector<uint> S;
};