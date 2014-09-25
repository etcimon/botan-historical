/*
* MARS
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* MARS, IBM's candidate for AES
*/
class MARS : public Block_Cipher_Fixed_Params<16, 16, 32, 4>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "MARS"; }
		BlockCipher* clone() const { return new MARS; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> EK;
};