/*
* AES using SSSE3
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* AES-128 using SSSE3
*/
class AES_128_SSSE3 : public Block_Cipher_Fixed_Params<16, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-128"; }
		BlockCipher* clone() const { return new AES_128_SSSE3; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u32bit> EK, DK;
};

/**
* AES-192 using SSSE3
*/
class AES_192_SSSE3 : public Block_Cipher_Fixed_Params<16, 24>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-192"; }
		BlockCipher* clone() const { return new AES_192_SSSE3; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u32bit> EK, DK;
};

/**
* AES-256 using SSSE3
*/
class AES_256_SSSE3 : public Block_Cipher_Fixed_Params<16, 32>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-256"; }
		BlockCipher* clone() const { return new AES_256_SSSE3; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u32bit> EK, DK;
};