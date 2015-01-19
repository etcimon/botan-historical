/*
* Read ref bytes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.get_byte;

import botan.constants;
public import botan.utils.mem_ops;
import botan.utils.types;
import std.bitmanip;
/**
* Byte extraction
* @param byte_num = which ubyte to extract, 0 == highest ubyte
* @param input = the value to extract from
* @return ubyte byte_num of input
*/
ubyte get_byte(T)(size_t byte_num, T input)
{
    return cast(ubyte)(input >> ( ( T.sizeof - 1 - (byte_num & (T.sizeof - 1) ) ) << 3) );
}