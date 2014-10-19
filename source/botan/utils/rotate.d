/*
* Word Rotation Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.rotate;

import botan.utils.types;
/**
* Bit rotation left
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated left by rot bits
*/
T rotate_left(T)(T input, size_t rot)
{
	if (rot == 0)
		return input;
	return cast(T)((input << rot) | (input >> (8*sizeof(T)-rot)));;
}

/**
* Bit rotation right
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated right by rot bits
*/
T rotate_right(T)(T input, size_t rot)
{
	if (rot == 0)
		return input;
	return cast(T)((input >> rot) | (input << (8*sizeof(T)-rot)));
}