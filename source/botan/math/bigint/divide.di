/*
* Division
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/bigint.h>
/**
* BigInt Division
* @param x an integer
* @param y a non-zero integer
* @param q will be set to x / y
* @param r will be set to x % y
*/
void divide(in BigInt x,
							 const BigInt& y,
							 BigInt& q,
							 BigInt& r);