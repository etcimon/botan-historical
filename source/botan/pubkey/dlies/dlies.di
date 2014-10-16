/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pubkey;
import botan.mac.mac;
import botan.kdf.kdf;
/**
* DLIES Encryption
*/
class DLIES_Encryptor : PK_Encryptor
{
	public:
		DLIES_Encryptor(in PK_Key_Agreement_Key,
							 KDF kdf,
							 MessageAuthenticationCode mac,
							 size_t mac_key_len = 20);

		void set_other_key(in Vector!ubyte);
	private:
		Vector!ubyte enc(const ubyte[], size_t,
									 RandomNumberGenerator) const;

		size_t maximum_input_size() const;

		Vector!ubyte other_key, my_key;

		PK_Key_Agreement ka;
		Unique!KDF kdf;
		Unique!MessageAuthenticationCode mac;
		size_t mac_keylen;
};

/**
* DLIES Decryption
*/
class DLIES_Decryptor : PK_Decryptor
{
	public:
		DLIES_Decryptor(in PK_Key_Agreement_Key,
							 KDF kdf,
							 MessageAuthenticationCode mac,
							 size_t mac_key_len = 20);

	private:
		SafeVector!ubyte dec(const ubyte[], size_t) const;

		Vector!ubyte my_key;

		PK_Key_Agreement ka;
		Unique!KDF kdf;
		Unique!MessageAuthenticationCode mac;
		size_t mac_keylen;
};