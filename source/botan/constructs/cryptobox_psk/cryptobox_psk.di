/*
* Cryptobox Message Routines
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <string>
#include <botan/rng.h>
#include <botan/symkey.h>
/**
* This namespace holds various high-level crypto functions
*/
namespace CryptoBox {

/**
* Encrypt a message using a shared secret key
* @param input the input data
* @param input_len the length of input in bytes
* @param key the key used to encrypt the message
* @param rng a ref to a random number generator, such as AutoSeeded_RNG
*/
Vector!( byte ) encrypt(in byte[] input, size_t input_len,
												const SymmetricKey& key,
												RandomNumberGenerator& rng);

/**
* Encrypt a message using a shared secret key
* @param input the input data
* @param input_len the length of input in bytes
* @param key the key used to encrypt the message
* @param rng a ref to a random number generator, such as AutoSeeded_RNG
*/
SafeVector!byte decrypt(in byte[] input, size_t input_len,
												  const SymmetricKey& key);

}