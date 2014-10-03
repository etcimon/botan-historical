/*
* AES using SSSE3
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* AES-128 using SSSE3
*/
class AES_128_SSSE3 : public Block_Cipher_Fixed_Params!(16, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-128"; }
		BlockCipher clone() const { return new AES_128_SSSE3; }
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!uint EK, DK;
};

/**
* AES-192 using SSSE3
*/
class AES_192_SSSE3 : public Block_Cipher_Fixed_Params!(16, 24)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-192"; }
		BlockCipher clone() const { return new AES_192_SSSE3; }
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!uint EK, DK;
};

/**
* AES-256 using SSSE3
*/
class AES_256_SSSE3 : public Block_Cipher_Fixed_Params!(16, 32)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-256"; }
		BlockCipher clone() const { return new AES_256_SSSE3; }
	private:
		void key_schedule(in byte*, size_t);

		secure_vector!uint EK, DK;
};