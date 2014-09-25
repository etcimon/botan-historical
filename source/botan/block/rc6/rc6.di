/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_RC6_H__

#include <botan/block_cipher.h>
/**
* RC6, Ron Rivest's AES candidate
*/
class RC6 : public Block_Cipher_Fixed_Params<16, 1, 32>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();
		string name() const { return "RC6"; }
		BlockCipher* clone() const { return new RC6; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u32bit> S;
};