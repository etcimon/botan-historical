/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_CAST128_H__

#include <botan/block_cipher.h>
/**
* CAST-128
*/
class CAST_128 : public Block_Cipher_Fixed_Params<8, 11, 16>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();
		string name() const { return "CAST-128"; }
		BlockCipher* clone() const { return new CAST_128; }

	private:
		void key_schedule(const byte[], size_t);

		static void cast_ks(secure_vector<u32bit>& ks,
								  secure_vector<u32bit>& user_key);

		secure_vector<u32bit> MK;
		SafeArray!byte RK;
};