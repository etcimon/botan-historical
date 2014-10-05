/*
* SAFER-SK
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* SAFER-SK
*/
class SAFER_SK : public Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const;
		BlockCipher clone() const;

		/**
		* @param rounds the number of rounds to use - must be between 1
		* and 13
		*/
		SAFER_SK(size_t rounds);
	private:
		void key_schedule(in ubyte*, size_t);

		size_t rounds;
		SafeVector!ubyte EK;
};