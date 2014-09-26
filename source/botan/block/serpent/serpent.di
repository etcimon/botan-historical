/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* Serpent, an AES finalist
*/
class Serpent : public Block_Cipher_Fixed_Params<16, 16, 32, 8>
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "Serpent"; }
		BlockCipher* clone() const { return new Serpent; }
	protected:
		/**
		* For use by subclasses using SIMD, asm, etc
		* @return const reference to the key schedule
		*/
		const secure_vector<uint>& get_round_keys() const
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
		void key_schedule(in byte* key);
		secure_vector<uint> round_key;
};