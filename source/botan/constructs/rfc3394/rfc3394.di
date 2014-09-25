/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/symkey.h>
class Algorithm_Factory;

/**
* Encrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the plaintext key to encrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key encrypted under kek
*/
SafeVector!byte rfc3394_keywrap(in SafeVector!byte key,
															const SymmetricKey& kek,
															Algorithm_Factory& af);

/**
* Decrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the encrypted key to decrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key decrypted under kek
*/
SafeVector!byte rfc3394_keyunwrap(in SafeVector!byte key,
															  const SymmetricKey& kek,
															  Algorithm_Factory& af);