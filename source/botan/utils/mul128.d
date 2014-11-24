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
void mul64x64_128(ulong a, ulong b, ref ulong[2] res)
{
    uint[] res_ = (cast(uint*)res.ptr)[0 .. 4];
    uint[] a_ = (cast(uint*)a.ptr)[0 .. 2];
    uint[] b_ = (cast(uint*)b.ptr)[0 .. 2];

    res[] = a_[] * b[];
}