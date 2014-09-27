/*
* RC2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* RC2
*/
class RC2 : public Block_Cipher_Fixed_Params<8, 1, 32>
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

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
		void key_schedule(in byte*, size_t);

		secure_vector!ushort K;
};