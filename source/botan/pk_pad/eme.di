/*
* EME Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <botan/rng.h>
/**
* Encoding Method for Encryption
*/
class EME
{
	public:
		/**
		* Return the maximum input size in bytes we can support
		* @param keybits the size of the key in bits
		* @return upper bound of input in bytes
		*/
		abstract size_t maximum_input_size(size_t keybits) const = 0;

		/**
		* Encode an input
		* @param in the plaintext
		* @param in_length length of plaintext in bytes
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		SafeArray!byte encode(in byte[] in,
										  size_t in_length,
										  size_t key_length,
										  RandomNumberGenerator& rng) const;

		/**
		* Encode an input
		* @param in the plaintext
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		SafeArray!byte encode(in SafeArray!byte in,
										  size_t key_length,
										  RandomNumberGenerator& rng) const;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param in_length length of encoded plaintext in bytes
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		SafeArray!byte decode(in byte[] in,
										  size_t in_length,
										  size_t key_length) const;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		SafeArray!byte decode(in SafeArray!byte in,
										  size_t key_length) const;

		abstract ~EME() {}
	private:
		/**
		* Encode an input
		* @param in the plaintext
		* @param in_length length of plaintext in bytes
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		abstract SafeArray!byte pad(in byte[] in,
												 size_t in_length,
												 size_t key_length,
												 RandomNumberGenerator& rng) const = 0;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param in_length length of encoded plaintext in bytes
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		abstract SafeArray!byte unpad(in byte[] in,
													size_t in_length,
													size_t key_length) const = 0;
};

/**
* Factory method for EME (message-encoding methods for encryption) objects
* @param algo_spec the name of the EME to create
* @return pointer to newly allocated object of that type
*/
EME*  get_eme(in string algo_spec);