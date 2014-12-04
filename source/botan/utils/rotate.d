/*
* Word Rotation Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.rotate;

import botan.utils.types;
pure:

/**
* Bit rotation left
* @param input = the input word
* @param rot = the number of bits to rotate
* @return input rotated left by rot bits
*/
T rotateLeft(T)(T input, size_t rot)
{
    if (rot == 0)
        return input;
    return cast(T)((input << rot) | (input >> (8*T.sizeof-rot)));
}

/**
* Bit rotation right
* @param input = the input word
* @param rot = the number of bits to rotate
* @return input rotated right by rot bits
*/
T rotateRight(T)(T input, size_t rot)
{
    if (rot == 0)
        return input;
    return cast(T)((input >> rot) | (input << (8*T.sizeof-rot)));
}