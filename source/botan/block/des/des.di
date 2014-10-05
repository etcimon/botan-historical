/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* DES
*/
class DES : public Block_Cipher_Fixed_Params!(8, 8)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "DES"; }
		BlockCipher clone() const { return new DES; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint round_key;
};

/**
* Triple DES
*/
class TripleDES : public Block_Cipher_Fixed_Params!(8, 16, 24, 8)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "TripleDES"; }
		BlockCipher clone() const { return new TripleDES; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint round_key;
};

/*
* DES Tables
*/
extern const uint DES_SPBOX1[256];
extern const uint DES_SPBOX2[256];
extern const uint DES_SPBOX3[256];
extern const uint DES_SPBOX4[256];
extern const uint DES_SPBOX5[256];
extern const uint DES_SPBOX6[256];
extern const uint DES_SPBOX7[256];
extern const uint DES_SPBOX8[256];

extern const ulong DES_IPTAB1[256];
extern const ulong DES_IPTAB2[256];
extern const ulong DES_FPTAB1[256];
extern const ulong DES_FPTAB2[256];