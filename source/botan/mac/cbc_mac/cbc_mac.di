/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_CBC_MAC_H__

#include <botan/mac.h>
#include <botan/block_cipher.h>
/**
* CBC-MAC
*/
class CBC_MAC : public MessageAuthenticationCode
{
	public:
		string name() const;
		MessageAuthenticationCode* clone() const;
		size_t output_length() const { return m_cipher->block_size(); }
		void clear();

		Key_Length_Specification key_spec() const
		{
			return m_cipher->key_spec();
		}

		/**
		* @param cipher the underlying block cipher to use
		*/
		CBC_MAC(BlockCipher* cipher);

	private:
		void add_data(const byte[], size_t);
		void final_result(byte[]);
		void key_schedule(const byte[], size_t);

		std::unique_ptr<BlockCipher> m_cipher;
		SafeArray!byte m_state;
		size_t m_position = 0;
};