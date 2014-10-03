/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pk_keys;
namespace KeyPair {

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param key the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
bool
encryption_consistency_check(RandomNumberGenerator rng,
									  in Private_Key key,
									  in string padding);

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param key the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
bool
signature_consistency_check(RandomNumberGenerator rng,
									 in Private_Key key,
									 in string padding);

}