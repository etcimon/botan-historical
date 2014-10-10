/*
* Integer Rounding Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.rounding;

import botan.types;
/**
* Round up
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded up to a multiple of align_to
*/
T round_up(T)(T n, T align_to)
{
	if (align_to == 0)
		return n;

	if (n % align_to || n == 0)
		n += align_to - (n % align_to);
	return n;
}

/**
* Round down
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded down to a multiple of align_to
*/
T round_down(T)(T n, T align_to)
{
	if (align_to == 0)
		return n;

	return (n - (n % align_to));
}

/**
* Clamp
*/
size_t clamp(size_t n, size_t lower_bound, size_t upper_bound)
{
	if (n < lower_bound)
		return lower_bound;
	if (n > upper_bound)
		return upper_bound;
	return n;
}