/*
* Hash Function Identification
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_HASHID_H__

#include <botan/secmem.h>
#include <string>
/**
* Return the PKCS #1 hash identifier
* @see RFC 3447 section 9.2
* @param hash_name the name of the hash function
* @return byte sequence identifying the hash
* @throw Invalid_Argument if the hash has no known PKCS #1 hash id
*/
std::vector<byte> pkcs_hash_id(in string hash_name);

/**
* Return the IEEE 1363 hash identifier
* @param hash_name the name of the hash function
* @return byte code identifying the hash, or 0 if not known
*/
byte ieee1363_hash_id(in string hash_name);