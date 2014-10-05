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
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "Twofish"; }
		BlockCipher clone() const { return new Twofish; }
	private:
		void key_schedule(in ubyte*, size_t);

		static void rs_mul(ubyte[4], ubyte, size_t);

		static const uint MDS0[256];
		static const uint MDS1[256];
		static const uint MDS2[256];
		static const uint MDS3[256];
		static const ubyte Q0[256];
		static const ubyte Q1[256];
		static const ubyte RS[32];
		static const ubyte EXP_TO_POLY[255];
		static const ubyte POLY_TO_EXP[255];

		secure_vector!uint SB, RK;
};