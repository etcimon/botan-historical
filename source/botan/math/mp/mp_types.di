/*
* Low Level MPI Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import botan.mul128;
#if (BOTAN_MP_WORD_BITS == 8)
  typedef ubyte word;
  typedef ushort dword;
  #define BOTAN_HAS_MP_DWORD
#elif (BOTAN_MP_WORD_BITS == 16)
  typedef ushort word;
  typedef uint dword;
  #define BOTAN_HAS_MP_DWORD
#elif (BOTAN_MP_WORD_BITS == 32)
  typedef uint word;
  typedef ulong dword;
  #define BOTAN_HAS_MP_DWORD
#elif (BOTAN_MP_WORD_BITS == 64)
  typedef ulong word;

  #if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
	 typedef uint128_t dword;
	 #define BOTAN_HAS_MP_DWORD
  #endif

#else
  #error BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64
#endif

const word MP_WORD_MASK = ~cast(word)(0);
const word MP_WORD_TOP_BIT = cast(word)(1) << (8*sizeof(word) - 1);
const word MP_WORD_MAX = MP_WORD_MASK;