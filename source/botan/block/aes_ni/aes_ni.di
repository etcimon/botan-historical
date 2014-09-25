/*
* AES using AES-NI instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* AES-128 using AES-NI
*/
class AES_128_NI : public Block_Cipher_Fixed_Params<16, 16>
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-128"; }
		BlockCipher* clone() const { return new AES_128_NI; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> EK, DK;
};

/**
* AES-192 using AES-NI
*/
class AES_192_NI : public Block_Cipher_Fixed_Params<16, 24>
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-192"; }
		BlockCipher* clone() const { return new AES_192_NI; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> EK, DK;
};

/**
* AES-256 using AES-NI
*/
class AES_256_NI : public Block_Cipher_Fixed_Params<16, 32>
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "AES-256"; }
		BlockCipher* clone() const { return new AES_256_NI; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<uint> EK, DK;
};