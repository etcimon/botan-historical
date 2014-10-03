/*
* EME Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.rng;
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
		abstract size_t maximum_input_size(size_t keybits) const;

		/**
		* Encode an input
		* @param in the plaintext
		* @param in_length length of plaintext in bytes
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		SafeVector!byte encode(in byte* in,
										  size_t in_length,
										  size_t key_length,
										  RandomNumberGenerator rng) const;

		/**
		* Encode an input
		* @param in the plaintext
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		SafeVector!byte encode(in SafeVector!byte in,
										  size_t key_length,
										  RandomNumberGenerator rng) const;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param in_length length of encoded plaintext in bytes
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		SafeVector!byte decode(in byte* in,
										  size_t in_length,
										  size_t key_length) const;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		SafeVector!byte decode(in SafeVector!byte in,
										  size_t key_length) const;

		~this() {}
	private:
		/**
		* Encode an input
		* @param in the plaintext
		* @param in_length length of plaintext in bytes
		* @param key_length length of the key in bits
		* @param rng a random number generator
		* @return encoded plaintext
		*/
		abstract SafeVector!byte pad(in byte* in,
												 size_t in_length,
												 size_t key_length,
												 RandomNumberGenerator rng) const;

		/**
		* Decode an input
		* @param in the encoded plaintext
		* @param in_length length of encoded plaintext in bytes
		* @param key_length length of the key in bits
		* @return plaintext
		*/
		abstract SafeVector!byte unpad(in byte* in,
													size_t in_length,
													size_t key_length) const;
};

/**
* Factory method for EME (message-encoding methods for encryption) objects
* @param algo_spec the name of the EME to create
* @return pointer to newly allocated object of that type
*/
EME*  get_eme(in string algo_spec);