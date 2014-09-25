/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* Twofish, an AES finalist
*/
class Twofish : public Block_Cipher_Fixed_Params<16, 16, 32, 8>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "Twofish"; }
		BlockCipher* clone() const { return new Twofish; }
	private:
		void key_schedule(const byte[], size_t);

		static void rs_mul(byte[4], byte, size_t);

		static const u32bit MDS0[256];
		static const u32bit MDS1[256];
		static const u32bit MDS2[256];
		static const u32bit MDS3[256];
		static const byte Q0[256];
		static const byte Q1[256];
		static const byte RS[32];
		static const byte EXP_TO_POLY[255];
		static const byte POLY_TO_EXP[255];

		secure_vector<u32bit> SB, RK;
};