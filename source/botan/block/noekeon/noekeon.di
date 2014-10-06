/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* Noekeon
*/
class Noekeon : Block_Cipher_Fixed_Params!(16, 16)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "Noekeon"; }
		BlockCipher clone() const { return new Noekeon; }
	package:
		/**
		* The Noekeon round constants
		*/
		static const ubyte RC[17];

		/**
		* @return const reference to encryption subkeys
		*/
		const secure_vector!uint& get_EK() const { return EK; }

		/**
		* @return const reference to decryption subkeys
		*/
		const secure_vector!uint& get_DK() const { return DK; }

	private:
		void key_schedule(in ubyte*, size_t);
		secure_vector!uint EK, DK;
};