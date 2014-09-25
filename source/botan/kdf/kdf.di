/*
* Key Derivation Function interfaces
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_KDF_BASE_H__

#include <botan/secmem.h>
#include <botan/types.h>
#include <string>
/**
* Key Derivation Function
*/
class KDF
{
	public:
		abstract ~KDF() {}

		abstract string name() const = 0;

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		SafeArray!byte derive_key(size_t key_len,
												in SafeArray!byte secret,
												in string salt = "") const
		{
			return derive_key(key_len, &secret[0], secret.size(),
									reinterpret_cast<const byte*>(salt.data()),
									salt.length());
		}

		/**
		* Derive a key
		* @param key_len the desired output length in bytes
		* @param secret the secret input
		* @param salt a diversifier
		*/
		template<typename Alloc, typename Alloc2>
		SafeArray!byte derive_key(size_t key_len,
												 const std::vector<byte, Alloc>& secret,
												 const std::vector<byte, Alloc2>& salt) const
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
		SafeArray!byte derive_key(size_t key_len,
												in SafeArray!byte secret,
												const byte salt[],
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
		SafeArray!byte derive_key(size_t key_len,
												const byte secret[],
												size_t secret_len,
												in string salt = "") const
		{
			return derive_key(key_len, secret, secret_len,
									reinterpret_cast<const byte*>(salt.data()),
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
		SafeArray!byte derive_key(size_t key_len,
												const byte secret[],
												size_t secret_len,
												const byte salt[],
												size_t salt_len) const
		{
			return derive(key_len, secret, secret_len, salt, salt_len);
		}

		abstract KDF* clone() const = 0;
	private:
		abstract SafeArray!byte
			derive(size_t key_len,
					 const byte secret[], size_t secret_len,
					 const byte salt[], size_t salt_len) const = 0;
};

/**
* Factory method for KDF (key derivation function)
* @param algo_spec the name of the KDF to create
* @return pointer to newly allocated object of that type
*/
KDF*  get_kdf(in string algo_spec);