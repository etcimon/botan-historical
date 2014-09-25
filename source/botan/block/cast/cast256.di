/*
* CAST-256
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* CAST-256
*/
class CAST_256 : public Block_Cipher_Fixed_Params<16, 4, 32, 4>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "CAST-256"; }
		BlockCipher* clone() const { return new CAST_256; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u32bit> MK;
		SafeArray!byte RK;
};