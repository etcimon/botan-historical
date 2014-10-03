/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* IDEA
*/
class IDEA : public Block_Cipher_Fixed_Params!(8, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "IDEA"; }
		BlockCipher clone() const { return new IDEA; }
	package:
		/**
		* @return const reference to encryption subkeys
		*/
		const secure_vector!ushort& get_EK() const { return EK; }

		/**
		* @return const reference to decryption subkeys
		*/
		const secure_vector!ushort& get_DK() const { return DK; }

	private:
		void key_schedule(in byte*, size_t);

		secure_vector!ushort EK, DK;
};