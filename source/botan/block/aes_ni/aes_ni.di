/*
* AES using AES-NI instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* AES-128 using AES-NI
*/
class AES_128_NI : public Block_Cipher_Fixed_Params!(16, 16)
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-128"; }
		BlockCipher clone() const { return new AES_128_NI; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint EK, DK;
};

/**
* AES-192 using AES-NI
*/
class AES_192_NI : public Block_Cipher_Fixed_Params!(16, 24)
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-192"; }
		BlockCipher clone() const { return new AES_192_NI; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint EK, DK;
};

/**
* AES-256 using AES-NI
*/
class AES_256_NI : public Block_Cipher_Fixed_Params!(16, 32)
{
	public:
		size_t parallelism() const { return 4; }

		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "AES-256"; }
		BlockCipher clone() const { return new AES_256_NI; }
	private:
		void key_schedule(in ubyte*, size_t);

		secure_vector!uint EK, DK;
};