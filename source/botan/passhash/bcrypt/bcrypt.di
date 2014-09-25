/*
* Bcrypt Password Hashing
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_BCRYPT_H__

#include <botan/rng.h>
/**
* Create a password hash using Bcrypt
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
*
* @see http://www.usenix.org/events/usenix99/provos/provos_html/
*/
string generate_bcrypt(in string password,
												  RandomNumberGenerator& rng,
												  u16bit work_factor = 10);

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool check_bcrypt(in string password,
									 in string hash);