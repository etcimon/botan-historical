/*
* AES
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_AES_H__

#include <botan/block_cipher.h>
/**
* AES-128
*/
class AES_128 : public Block_Cipher_Fixed_Params<16, 16>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();

		string name() const { return "AES-128"; }
		BlockCipher* clone() const { return new AES_128; }
	private:
		void key_schedule(const byte key[], size_t length);

		secure_vector<u32bit> EK, DK;
		SafeArray!byte ME, MD;
};

/**
* AES-192
*/
class AES_192 : public Block_Cipher_Fixed_Params<16, 24>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();

		string name() const { return "AES-192"; }
		BlockCipher* clone() const { return new AES_192; }
	private:
		void key_schedule(const byte key[], size_t length);

		secure_vector<u32bit> EK, DK;
		SafeArray!byte ME, MD;
};

/**
* AES-256
*/
class AES_256 : public Block_Cipher_Fixed_Params<16, 32>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();

		string name() const { return "AES-256"; }
		BlockCipher* clone() const { return new AES_256; }
	private:
		void key_schedule(const byte key[], size_t length);

		secure_vector<u32bit> EK, DK;
		SafeArray!byte ME, MD;
};