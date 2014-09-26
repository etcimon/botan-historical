/*
* Rivest's Package Tranform
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
#include <botan/rng.h>
/**
* Rivest's Package Tranform
* @param rng the random number generator to use
* @param cipher the block cipher to use
* @param input the input data buffer
* @param input_len the length of the input data in bytes
* @param output the output data buffer (must be at least
*		  input_len + cipher->BLOCK_SIZE bytes long)
*/
void aont_package(RandomNumberGenerator& rng,
									 BlockCipher* cipher,
									 in byte* input, size_t input_len,
									 byte* output);

/**
* Rivest's Package Tranform (Inversion)
* @param cipher the block cipher to use
* @param input the input data buffer
* @param input_len the length of the input data in bytes
* @param output the output data buffer (must be at least
*		  input_len - cipher->BLOCK_SIZE bytes long)
*/
void aont_unpackage(BlockCipher* cipher,
										in byte* input, size_t input_len,
										byte* output);