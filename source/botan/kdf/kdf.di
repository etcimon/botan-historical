/*
* Key Derivation Function interfaces
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.secmem;
import botan.types;
import string;
/**
* Key Derivation Function
*/
class KDF
{
	public:
		abstract ~KDF() {}

		abstract string name() const;

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		SafeVector!byte derive_key(size_t key_len,
									in SafeVector!byte secret,
									in string salt = "") const
		{
			return derive_key(key_len, &secret[0], secret.size(),
									cast(const byte*)(salt.data()),
									salt.length());
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		
		SafeVector!byte derive_key(Alloc, Alloc2)(size_t key_len,
													 in Vector!( byte, Alloc ) secret,
													 in Vector!( byte, Alloc2 ) salt) const
		{
			return derive_key(key_len,
									&secret[0], secret.size(),
									&salt[0], salt.size());
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		* @param salt_len size of salt in bytes
		*/
		SafeVector!byte derive_key(size_t key_len,
									in SafeVector!byte secret,
									in byte* salt,
									size_t salt_len) const
		{
			return derive_key(key_len,
								&secret[0], secret.size(),
								salt, salt_len);
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param secret_len size of secret in bytes
		* @param salt a diversifier
		*/
		SafeVector!byte derive_key(size_t key_len,
									in byte* secret,
									size_t secret_len,
									in string salt = "") const
		{
			return derive_key(key_len, secret, secret_len,
									cast(const byte*)(salt.data()),
									salt.length());
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param secret_len size of secret in bytes
		* @param salt a diversifier
		* @param salt_len size of salt in bytes
		*/
		SafeVector!byte derive_key(size_t key_len,
									in byte* secret,
									size_t secret_len,
									in byte* salt,
									size_t salt_len) const
		{
			return derive(key_len, secret, secret_len, salt, salt_len);
		}

		abstract KDF* clone() const;
	private:
		abstract SafeVector!byte
			derive(size_t key_len,
					 in byte* secret, size_t secret_len,
					 in byte* salt, size_t salt_len) const;
};

/**
* Factory method for KDF (key derivation function)
* @param algo_spec the name of the KDF to create
* @return pointer to newly allocated object of that type
*/
KDF*  get_kdf(in string algo_spec);