/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pubkey;
import botan.mac;
import botan.kdf;
/**
* DLIES Encryption
*/
class DLIES_Encryptor : public PK_Encryptor
{
	public:
		DLIES_Encryptor(in PK_Key_Agreement_Key,
							 KDF* kdf,
							 MessageAuthenticationCode mac,
							 size_t mac_key_len = 20);

		void set_other_key(in Vector!byte);
	private:
		Vector!byte enc(const byte[], size_t,
									 RandomNumberGenerator) const;

		size_t maximum_input_size() const;

		Vector!byte other_key, my_key;

		PK_Key_Agreement ka;
		Unique!KDF kdf;
		Unique!MessageAuthenticationCode mac;
		size_t mac_keylen;
};

/**
* DLIES Decryption
*/
class DLIES_Decryptor : public PK_Decryptor
{
	public:
		DLIES_Decryptor(in PK_Key_Agreement_Key,
							 KDF* kdf,
							 MessageAuthenticationCode mac,
							 size_t mac_key_len = 20);

	private:
		SafeVector!byte dec(const byte[], size_t) const;

		Vector!byte my_key;

		PK_Key_Agreement ka;
		Unique!KDF kdf;
		Unique!MessageAuthenticationCode mac;
		size_t mac_keylen;
};