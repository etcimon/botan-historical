/*
* Bit/Word Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.bit_ops;

import botan.utils.types;
/**
* Power of 2 test. T should be an uinteger type
* @param arg an integer value
* @return true iff arg is 2^n for some n > 0
*/
bool is_power_of_2(T)(T arg)
{
	return ((arg != 0 && arg != 1) && ((arg & (arg-1)) == 0));
}

/**
* Return the index of the highest set bit
* T is an uinteger type
* @param n an integer value
* @return index of the highest set bit in n
*/
size_t high_bit(T)(T n)
{
	for (size_t i = 8*sizeof(T); i > 0; --i)
		if ((n >> (i - 1)) & 0x01)
			return i;
	return 0;
}

/**
* Return the index of the lowest set bit
* T is an uinteger type
* @param n an integer value
* @return index of the lowest set bit in n
*/
size_t low_bit(T)(T n)
{
	for (size_t i = 0; i != 8*sizeof(T); ++i)
		if ((n >> i) & 0x01)
			return (i + 1);
	return 0;
}

/**
* Return the number of significant bytes in n
* @param n an integer value
* @return number of significant bytes in n
*/
size_t significant_bytes(T)(T n)
{
	for (size_t i = 0; i != sizeof(T); ++i)
		if (get_byte(i, n))
			return sizeof(T)-i;
	return 0;
}

/**
* Compute Hamming weights
* @param n an integer value
* @return number of bits in n set to 1
*/
size_t hamming_weight(T)(T n)
{
	immutable ubyte[] NIBBLE_WEIGHTS = {
		0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

	size_t weight = 0;
	for (size_t i = 0; i != 2*sizeof(T); ++i)
		weight += NIBBLE_WEIGHTS[(n >> (4*i)) & 0x0F];
	return weight;
}

/**
* Count the trailing zero bits in n
* @param n an integer value
* @return maximum x st 2^x divides n
*/
size_t ctz(T)(T n)
{
	for (size_t i = 0; i != 8*sizeof(T); ++i)
		if ((n >> i) & 0x01)
			return i;
	return 8*sizeof(T);
}