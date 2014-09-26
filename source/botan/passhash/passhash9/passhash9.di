/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/rng.h>
/**
* Create a password hash using PBKDF2
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param alg_id specifies which PRF to use with PBKDF2
*		  0 is HMAC(SHA-1)
*		  1 is HMAC(SHA-256)
*		  2 is CMAC(Blowfish)
*		  3 is HMAC(SHA-384)
*		  4 is HMAC(SHA-512)
*		  all other values are currently undefined
*/
string generate_passhash9(in string password,
													  RandomNumberGenerator& rng,
													  ushort work_factor = 10,
													  byte alg_id = 1);

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool check_passhash9(in string password,
										 in string hash);