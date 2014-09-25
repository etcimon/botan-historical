/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/mac.h>
#include <botan/hash.h>
/**
* HMAC
*/
class HMAC : public MessageAuthenticationCode
{
	public:
		void clear();
		string name() const;
		MessageAuthenticationCode* clone() const;

		size_t output_length() const { return m_hash->output_length(); }

		Key_Length_Specification key_spec() const
		{
			// Absurd max length here is to support PBKDF2
			return Key_Length_Specification(0, 512);
		}

		/**
		* @param hash the hash to use for HMACing
		*/
		HMAC(HashFunction* hash);

		HMAC(const HMAC&) = delete;
		HMAC& operator=(const HMAC&) = delete;
	private:
		void add_data(const byte[], size_t);
		void final_result(byte[]);
		void key_schedule(const byte[], size_t);

		std::unique_ptr<HashFunction> m_hash;
		SafeArray!byte m_ikey, m_okey;
};