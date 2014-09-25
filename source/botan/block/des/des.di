/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* DES
*/
class DES : public Block_Cipher_Fixed_Params<8, 8>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "DES"; }
		BlockCipher* clone() const { return new DES; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> round_key;
};

/**
* Triple DES
*/
class TripleDES : public Block_Cipher_Fixed_Params<8, 16, 24, 8>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "TripleDES"; }
		BlockCipher* clone() const { return new TripleDES; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> round_key;
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

extern const u64bit DES_IPTAB1[256];
extern const u64bit DES_IPTAB2[256];
extern const u64bit DES_FPTAB1[256];
extern const u64bit DES_FPTAB2[256];