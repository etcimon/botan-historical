/*
* Camellia
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* Camellia-128
*/
class Camellia_128 : public Block_Cipher_Fixed_Params<16, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "Camellia-128"; }
		BlockCipher* clone() const { return new Camellia_128; }
	private:
		void key_schedule(in byte[] key);

		secure_vector<u64bit> SK;
};

/**
* Camellia-192
*/
class Camellia_192 : public Block_Cipher_Fixed_Params<16, 24>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "Camellia-192"; }
		BlockCipher* clone() const { return new Camellia_192; }
	private:
		void key_schedule(in byte[] key);

		secure_vector<u64bit> SK;
};

/**
* Camellia-256
*/
class Camellia_256 : public Block_Cipher_Fixed_Params<16, 32>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "Camellia-256"; }
		BlockCipher* clone() const { return new Camellia_256; }
	private:
		void key_schedule(in byte[] key);

		secure_vector<u64bit> SK;
};