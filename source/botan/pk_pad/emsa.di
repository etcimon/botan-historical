/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_PUBKEY_EMSA_H__

#include <botan/secmem.h>
#include <botan/rng.h>
/**
* Encoding Method for Signatures, Appendix
*/
class EMSA
{
	public:
		/**
		* Add more data to the signature computation
		* @param input some data
		* @param length length of input in bytes
		*/
		abstract void update(const byte input[], size_t length) = 0;

		/**
		* @return raw hash
		*/
		abstract SafeArray!byte raw_data() = 0;

		/**
		* Return the encoding of a message
		* @param msg the result of raw_data()
		* @param output_bits the desired output bit size
		* @param rng a random number generator
		* @return encoded signature
		*/
		abstract SafeArray!byte encoding_of(in SafeArray!byte msg,
															size_t output_bits,
															RandomNumberGenerator& rng) = 0;

		/**
		* Verify the encoding
		* @param coded the received (coded) message representative
		* @param raw the computed (local, uncoded) message representative
		* @param key_bits the size of the key in bits
		* @return true if coded is a valid encoding of raw, otherwise false
		*/
		abstract bool verify(in SafeArray!byte coded,
								  in SafeArray!byte raw,
								  size_t key_bits) = 0;
		abstract ~EMSA() {}
};

/**
* Factory method for EMSA (message-encoding methods for signatures
* with appendix) objects
* @param algo_spec the name of the EME to create
* @return pointer to newly allocated object of that type
*/
EMSA* get_emsa(in string algo_spec);