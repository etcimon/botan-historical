/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.math.bigint.bigint;
import string;
/**
* @param x the secret (EC)DSA key
* @param q the group order
* @param h the message hash already reduced mod q
* @param hash the hash function used to generate h
*/
BigInt generate_rfc6979_nonce(in BigInt x,
													 const ref BigInt q,
													 const ref BigInt h,
													 in string hash);