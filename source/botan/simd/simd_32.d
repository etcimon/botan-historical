/*
* Lightweight wrappers for SIMD operations
* (C) 2009,2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_32;
import botan.utils.types;
import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2) {
    import botan.simd.simd_sse2;
	alias SIMD32 = SIMDSSE2; 
}
else static if (BOTAN_HAS_SIMD_ALTIVEC) {
      import botan.simd.simd_altivec;
	alias SIMD32 = SIMDAltivec;
}
else static if (BOTAN_HAS_SIMD_SCALAR) {
    import botan.simd.simd_scalar;
	alias SIMD32 = SIMDScalar!(uint,4); 
}
else
    static assert(false, "No SIMD defined");