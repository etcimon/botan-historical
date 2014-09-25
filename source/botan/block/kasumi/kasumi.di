/*
* KASUMI
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* KASUMI, the block cipher used in 3G telephony
*/
class KASUMI : public Block_Cipher_Fixed_Params<8, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "KASUMI"; }
		BlockCipher* clone() const { return new KASUMI; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u16bit> EK;
};