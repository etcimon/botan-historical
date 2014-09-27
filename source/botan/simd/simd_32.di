/*
* Lightweight wrappers for SIMD operations
* (C) 2009,2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;

#if defined(BOTAN_HAS_SIMD_SSE2)
  import botan.internal.simd_sse2;
   typedef SIMD_SSE2 SIMD_32; }

#elif defined(BOTAN_HAS_SIMD_ALTIVEC)
  import botan.internal.simd_altivec;
   typedef SIMD_Altivec SIMD_32; }

#elif defined(BOTAN_HAS_SIMD_SCALAR)
  import botan.internal.simd_scalar;
   typedef SIMD_Scalar<uint,4> SIMD_32; }

#else
  #error "No SIMD module defined"

#endif

#endif
