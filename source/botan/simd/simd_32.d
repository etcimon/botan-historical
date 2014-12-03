/*
* Lightweight wrappers for SIMD operations
* (C) 2009,2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_32;
import botan.utils.types;

static if (BOTAN_HAS_SIMD_SSE2) {
    import botan.simd.simd_sse2.simd_sse2;
    typedef SIMDSSE2 SIMD32; 
}
else static if (BOTAN_HAS_SIMD_ALTIVEC) {
      import botan.simd.simd_altivec.simd_altivec;
    typedef SIMDAltivec SIMD32;
}
else static if (BOTAN_HAS_SIMD_SCALAR) {
    import botan.simd.simd_scalar.simd_scalar;
    typedef SIMDScalar!(uint,4) SIMD32; 
}
else
    static assert(false, "No SIMD defined");