/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mac;
import botan.hash.hash;
/**
* HMAC
*/
class HMAC : MessageAuthenticationCode
{
	public:
		void clear();
		string name() const;
		MessageAuthenticationCode clone() const;

		size_t output_length() const { return m_hash.output_length(); }

		Key_Length_Specification key_spec() const
		{
			// Absurd max length here is to support PBKDF2
			return Key_Length_Specification(0, 512);
		}

		/**
		* @param hash the hash to use for HMACing
		*/
		HMAC(HashFunction hash);

		HMAC(in HMAC);
		HMAC& operator=(in HMAC);
	private:
		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);
		void key_schedule(const ubyte[], size_t);

		Unique!HashFunction m_hash;
		SafeVector!ubyte m_ikey, m_okey;
};