/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* TEA
*/
class TEA : public Block_Cipher_Fixed_Params<8, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "TEA"; }
		BlockCipher* clone() const { return new TEA; }
	private:
		void key_schedule(const byte[], size_t);
		secure_vector<uint> K;
};