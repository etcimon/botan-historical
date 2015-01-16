/*
* 64x64.128 bit multiply operation
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.mul128;

import botan.utils.types;

/**
* Perform a 64x64.128 bit multiplication
*/
void mul64x64_128(ulong a, ulong b, ref ulong[2] res) pure
{
    res[] = a*b;
}