/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* Block Cipher Cascade
*/
class Cascade_Cipher : BlockCipher
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		size_t block_size() const { return m_block; }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(m_cipher1.maximum_keylength() +
													  m_cipher2.maximum_keylength());
		}

		void clear();
		string name() const;
		BlockCipher clone() const;

		/**
		* Create a cascade of two block ciphers
		* @param cipher1 the first cipher
		* @param cipher2 the second cipher
		*/
		Cascade_Cipher(BlockCipher cipher1, BlockCipher cipher2);

		Cascade_Cipher(in Cascade_Cipher);
		Cascade_Cipher& operator=(in Cascade_Cipher);
	private:
		void key_schedule(in ubyte*, size_t);

		size_t m_block;
		Unique!BlockCipher m_cipher1, m_cipher2;
};
