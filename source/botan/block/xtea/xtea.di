/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* XTEA
*/
class XTEA : public Block_Cipher_Fixed_Params<8, 16>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		void clear();
		string name() const { return "XTEA"; }
		BlockCipher* clone() const { return new XTEA; }
	protected:
		/**
		* @return const reference to the key schedule
		*/
		const secure_vector<uint>& get_EK() const { return EK; }

	private:
		void key_schedule(const byte[], size_t);
		secure_vector<uint> EK;
};