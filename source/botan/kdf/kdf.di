/*
* Key Derivation Function interfaces
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.types;
import string;
/**
* Key Derivation Function
*/
class KDF
{
	public:
		~this() {}

		abstract string name() const;

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		SafeVector!ubyte derive_key(size_t key_len,
									in SafeVector!ubyte secret,
									in string salt = "") const
		{
			return derive_key(key_len, &secret[0], secret.size(),
									cast(const ubyte*)(salt.data()),
									salt.length());
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		
		SafeVector!ubyte derive_key(Alloc, Alloc2)(size_t key_len,
													 in Vector!( ubyte, Alloc ) secret,
													 in Vector!( ubyte, Alloc2 ) salt) const
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
		SafeVector!ubyte derive_key(size_t key_len,
									in SafeVector!ubyte secret,
									in ubyte* salt,
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
		SafeVector!ubyte derive_key(size_t key_len,
									in ubyte* secret,
									size_t secret_len,
									in string salt = "") const
		{
			return derive_key(key_len, secret, secret_len,
									cast(const ubyte*)(salt.data()),
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
		SafeVector!ubyte derive_key(size_t key_len,
									in ubyte* secret,
									size_t secret_len,
									in ubyte* salt,
									size_t salt_len) const
		{
			return derive(key_len, secret, secret_len, salt, salt_len);
		}

		abstract KDF* clone() const;
	private:
		abstract SafeVector!ubyte
			derive(size_t key_len,
					 in ubyte* secret, size_t secret_len,
					 in ubyte* salt, size_t salt_len) const;
};

/**
* Factory method for KDF (key derivation function)
* @param algo_spec the name of the KDF to create
* @return pointer to newly allocated object of that type
*/
KDF*  get_kdf(in string algo_spec);