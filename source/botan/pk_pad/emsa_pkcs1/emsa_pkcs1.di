/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
import botan.hash;
/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class EMSA_PKCS1v15 : EMSA
{
	public:
		/**
		* @param hash the hash object to use
		*/
		EMSA_PKCS1v15(HashFunction hash);

		void update(const ubyte[], size_t);

		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte, size_t,
												 RandomNumberGenerator rng);

		bool verify(in SafeVector!ubyte, in SafeVector!ubyte,
						size_t);
	private:
		Unique!HashFunction m_hash;
		Vector!ubyte m_hash_id;
};

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class EMSA_PKCS1v15_Raw : EMSA
{
	public:
		void update(const ubyte[], size_t);

		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte, size_t,
												 RandomNumberGenerator rng);

		bool verify(in SafeVector!ubyte, in SafeVector!ubyte,
						size_t);

	private:
		SafeVector!ubyte message;
};