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
    uint[] res_ = (cast(uint*)res.ptr)[0 .. 4];
    uint[] a_ = (cast(uint*)&a)[0 .. 2];
    uint[] b_ = (cast(uint*)&b)[0 .. 2];

    res_[] = a_[] * b_[];
}