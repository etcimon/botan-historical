/*
* RC2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* RC2
*/
class RC2 : public Block_Cipher_Fixed_Params<8, 1, 32>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		/**
		* Return the code of the effective key bits
		* @param bits key length
		* @return EKB code
		*/
		static byte EKB_code(size_t bits);

		void clear();
		string name() const { return "RC2"; }
		BlockCipher* clone() const { return new RC2; }
	private:
		void key_schedule(const byte[], size_t);

		secure_vector<u16bit> K;
};