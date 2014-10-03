/*
* AES
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* AES-128
*/
class AES_128 : public Block_Cipher_Fixed_Params!(16, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();

		string name() const { return "AES-128"; }
		BlockCipher clone() const { return new AES_128; }
	private:
		void key_schedule(in byte* key);

		secure_vector!uint EK, DK;
		SafeVector!byte ME, MD;
};

/**
* AES-192
*/
class AES_192 : public Block_Cipher_Fixed_Params!(16, 24)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();

		string name() const { return "AES-192"; }
		BlockCipher clone() const { return new AES_192; }
	private:
		void key_schedule(in byte* key);

		secure_vector!uint EK, DK;
		SafeVector!byte ME, MD;
};

/**
* AES-256
*/
class AES_256 : public Block_Cipher_Fixed_Params!(16, 32)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();

		string name() const { return "AES-256"; }
		BlockCipher clone() const { return new AES_256; }
	private:
		void key_schedule(in byte* key);

		secure_vector!uint EK, DK;
		SafeVector!byte ME, MD;
};