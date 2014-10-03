/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* Twofish, an AES finalist
*/
class Twofish : public Block_Cipher_Fixed_Params!(16, 16, 32, 8)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "Twofish"; }
		BlockCipher clone() const { return new Twofish; }
	private:
		void key_schedule(in byte*, size_t);

		static void rs_mul(byte[4], byte, size_t);

		static const uint MDS0[256];
		static const uint MDS1[256];
		static const uint MDS2[256];
		static const uint MDS3[256];
		static const byte Q0[256];
		static const byte Q1[256];
		static const byte RS[32];
		static const byte EXP_TO_POLY[255];
		static const byte POLY_TO_EXP[255];

		secure_vector!uint SB, RK;
};