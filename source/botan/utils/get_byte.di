/*
* Read ref bytes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
/**
* Byte extraction
* @param byte_num which ubyte to extract, 0 == highest ubyte
* @param input the value to extract from
* @return ubyte byte_num of input
*/
template<typename T>  ubyte get_byte(size_t byte_num, T input)
{
	return cast(ubyte)(
		input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3)
		);
}