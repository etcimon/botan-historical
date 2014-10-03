/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
import botan.mac;
/**
* A MAC only used in SSLv3. Do not use elsewhere! Use HMAC instead.
*/
class SSL3_MAC : public MessageAuthenticationCode
{
	public:
		string name() const;
		size_t output_length() const { return m_hash.output_length(); }
		MessageAuthenticationCode clone() const;

		void clear();

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(m_hash.output_length());
		}

		/**
		* @param hash the underlying hash to use
		*/
		SSL3_MAC(HashFunction hash);
	private:
		void add_data(const byte[], size_t);
		void final_result(byte[]);
		void key_schedule(const byte[], size_t);

		Unique!HashFunction m_hash;
		SafeVector!byte m_ikey, m_okey;
};