/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* Noekeon
*/
class Noekeon : public Block_Cipher_Fixed_Params<16, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "Noekeon"; }
		BlockCipher* clone() const { return new Noekeon; }
	protected:
		/**
		* The Noekeon round constants
		*/
		static const byte RC[17];

		/**
		* @return const reference to encryption subkeys
		*/
		const secure_vector<uint>& get_EK() const { return EK; }

		/**
		* @return const reference to decryption subkeys
		*/
		const secure_vector<uint>& get_DK() const { return DK; }

	private:
		void key_schedule(const byte[], size_t);
		secure_vector<uint> EK, DK;
};