/*
* CMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mac;
import botan.block_cipher;
/**
* CMAC, also known as OMAC1
*/
class CMAC : public MessageAuthenticationCode
{
	public:
		string name() const;
		size_t output_length() const { return m_cipher->block_size(); }
		MessageAuthenticationCode* clone() const;

		void clear();

		Key_Length_Specification key_spec() const
		{
			return m_cipher->key_spec();
		}

		/**
		* CMAC's polynomial doubling operation
		* @param in the input
		* @param polynomial the byte value of the polynomial
		*/
		static SafeVector!byte poly_double(in SafeVector!byte input);

		/**
		* @param cipher the underlying block cipher to use
		*/
		CMAC(BlockCipher* cipher);

		CMAC(in CMAC);
		CMAC& operator=(in CMAC);
	private:
		void add_data(const byte[], size_t);
		void final_result(byte[]);
		void key_schedule(const byte[], size_t);

		Unique!BlockCipher m_cipher;
		SafeVector!byte m_buffer, m_state, m_B, m_P;
		size_t m_position;
};