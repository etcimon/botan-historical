/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_EMSA_PKCS1_H__

#include <botan/emsa.h>
#include <botan/hash.h>
/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class EMSA_PKCS1v15 : public EMSA
{
	public:
		/**
		* @param hash the hash object to use
		*/
		EMSA_PKCS1v15(HashFunction* hash);

		void update(const byte[], size_t);

		SafeArray!byte raw_data();

		SafeArray!byte encoding_of(in SafeArray!byte, size_t,
												 RandomNumberGenerator& rng);

		bool verify(in SafeArray!byte, in SafeArray!byte,
						size_t);
	private:
		std::unique_ptr<HashFunction> m_hash;
		std::vector<byte> m_hash_id;
};

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class EMSA_PKCS1v15_Raw : public EMSA
{
	public:
		void update(const byte[], size_t);

		SafeArray!byte raw_data();

		SafeArray!byte encoding_of(in SafeArray!byte, size_t,
												 RandomNumberGenerator& rng);

		bool verify(in SafeArray!byte, in SafeArray!byte,
						size_t);

	private:
		SafeArray!byte message;
};