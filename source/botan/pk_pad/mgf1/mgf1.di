/*
* MGF1
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/kdf.h>
#include <botan/hash.h>
/**
* MGF1 from PKCS #1 v2.0
*/
void mgf1_mask(HashFunction& hash,
					in byte[] in,
					ref byte[] output);