/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mac;
import botan.block_cipher;
/**
* CBC-MAC
*/
class CBC_MAC : public MessageAuthenticationCode
{
	public:
		string name() const;
		MessageAuthenticationCode clone() const;
		size_t output_length() const { return m_cipher.block_size(); }
		void clear();

		Key_Length_Specification key_spec() const
		{
			return m_cipher.key_spec();
		}

		/**
		* @param cipher the underlying block cipher to use
		*/
		CBC_MAC(BlockCipher cipher);

	private:
		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);
		void key_schedule(const ubyte[], size_t);

		Unique!BlockCipher m_cipher;
		SafeVector!ubyte m_state;
		size_t m_position = 0;
};