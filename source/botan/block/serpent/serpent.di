/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block.block_cipher;
/**
* Serpent, an AES finalist
*/
class Serpent : Block_Cipher_Fixed_Params!(16, 16, 32, 8)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "Serpent"; }
		BlockCipher clone() const { return new Serpent; }
	package:
		/**
		* For use by subclasses using SIMD, asm, etc
		* @return const reference to the key schedule
		*/
		const secure_vector!uint& get_round_keys() const
		{ return round_key; }

		/**
		* For use by subclasses that implement the key schedule
		* @param ks is the new key schedule value to set
		*/
		void set_round_keys(const uint ks[132])
		{
			round_key.assign(&ks[0], &ks[132]);
		}

	private:
		void key_schedule(in ubyte* key);
		secure_vector!uint round_key;
};