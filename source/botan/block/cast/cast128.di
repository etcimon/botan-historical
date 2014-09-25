/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* CAST-128
*/
class CAST_128 : public Block_Cipher_Fixed_Params<8, 11, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "CAST-128"; }
		BlockCipher* clone() const { return new CAST_128; }

	private:
		void key_schedule(const byte[], size_t);

		static void cast_ks(secure_vector<uint>& ks,
								  secure_vector<uint>& user_key);

		secure_vector<uint> MK;
		SafeVector!byte RK;
};