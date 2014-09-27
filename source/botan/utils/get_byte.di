/*
* Read ref bytes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
/**
* Byte extraction
* @param byte_num which byte to extract, 0 == highest byte
* @param input the value to extract from
* @return byte byte_num of input
*/
template<typename T>  byte get_byte(size_t byte_num, T input)
{
	return cast(byte)(
		input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3)
		);
}