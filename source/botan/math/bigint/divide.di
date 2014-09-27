/*
* Division
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
/**
* BigInt Division
* @param x an integer
* @param y a non-zero integer
* @param q will be set to x / y
* @param r will be set to x % y
*/
void divide(in BigInt x,
							 ref const BigInt y,
							 ref BigInt q,
							 ref BigInt r);