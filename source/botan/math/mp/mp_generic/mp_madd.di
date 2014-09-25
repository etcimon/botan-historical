/*
* Lowest Level MPI Algorithms
* (C) 1999-2008,2013 Jack Lloyd
*	  2006 Luca Piccarreta
*
* Distributed under the terms of the botan license.
*/

#include <botan/mp_types.h>
extern "C" {

/*
* Word Multiply/Add
*/
inline word word_madd2(word a, word b, word* c)
{
#if defined(BOTAN_HAS_MP_DWORD)
	const dword s = cast(dword)(a) * b + *c;
	*c = cast(word)(s >> BOTAN_MP_WORD_BITS);
	return cast(word)(s);
#else
	static_assert(BOTAN_MP_WORD_BITS == 64, "Unexpected word size");

	word hi = 0, lo = 0;

	mul64x64_128(a, b, &lo, &hi);

	lo += *c;
	hi += (lo < *c); // carry?

	*c = hi;
	return lo;
#endif
}

/*
* Word Multiply/Add
*/
inline word word_madd3(word a, word b, word c, word* d)
{
#if defined(BOTAN_HAS_MP_DWORD)
	const dword s = cast(dword)(a) * b + c + *d;
	*d = cast(word)(s >> BOTAN_MP_WORD_BITS);
	return cast(word)(s);
#else
	static_assert(BOTAN_MP_WORD_BITS == 64, "Unexpected word size");

	word hi = 0, lo = 0;

	mul64x64_128(a, b, &lo, &hi);

	lo += c;
	hi += (lo < c); // carry?

	lo += *d;
	hi += (lo < *d); // carry?

	*d = hi;
	return lo;
#endif
}

}