/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* IDEA
*/
class IDEA : public Block_Cipher_Fixed_Params<8, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "IDEA"; }
		BlockCipher* clone() const { return new IDEA; }
	protected:
		/**
		* @return const reference to encryption subkeys
		*/
		const secure_vector<u16bit>& get_EK() const { return EK; }

		/**
		* @return const reference to decryption subkeys
		*/
		const secure_vector<u16bit>& get_DK() const { return DK; }

	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u16bit> EK, DK;
};