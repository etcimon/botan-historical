/*
* Low Level MPI Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.botan.math.mp.mp_types;
import botan.utils.types;
import botan.utils.mul128;
import botan.constants;

static if (BOTAN_MP_WORD_BITS == 8) {
	typedef ubyte word;
	typedef ushort dword;
	enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 16) {
	typedef ushort word;
	typedef uint dword;
	enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 32) {
	typedef uint word;
	typedef ulong dword;
	enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 64) {
	typedef ulong word;

	static if (BOTAN_TARGET_HAS_NATIVE_UINT128) {
		typedef uint128_t dword;
		enum BOTAN_HAS_MP_DWORD = 1;
	}

} else
	static assert(false, "BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64");


immutable word MP_WORD_MASK = ~cast(word)(0);
immutable word MP_WORD_TOP_BIT = cast(word)(1) << (8*(word).sizeof - 1);
immutable word MP_WORD_MAX = MP_WORD_MASK;