/*
* Cryptobox Message Routines
* (C) 2009 Jack Lloyd
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
* Encrypt a message using a passphrase
* @param input the input data
* @param input_len the length of input in bytes
* @param passphrase the passphrase used to encrypt the message
* @param rng a ref to a random number generator, such as AutoSeeded_RNG
*/
string encrypt(in byte[] input, size_t input_len,
										in string passphrase,
										RandomNumberGenerator& rng);/**
* Decrypt a message encrypted with CryptoBox::encrypt
* @param input the input data
* @param input_len the length of input in bytes
* @param passphrase the passphrase used to encrypt the message
*/
string decrypt(in byte[] input, size_t input_len,
										in string passphrase);

/**
* Decrypt a message encrypted with CryptoBox::encrypt
* @param input the input data
* @param passphrase the passphrase used to encrypt the message
*/
string decrypt(in string input,
										in string passphrase);

}