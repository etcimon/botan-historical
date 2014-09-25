/*
* Lightweight wrappers for SIMD operations
* (C) 2009,2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/types.h>

#if defined(BOTAN_HAS_SIMD_SSE2)
  #include <botan/internal/simd_sse2.h>
   typedef SIMD_SSE2 SIMD_32; }

#elif defined(BOTAN_HAS_SIMD_ALTIVEC)
  #include <botan/internal/simd_altivec.h>
   typedef SIMD_Altivec SIMD_32; }

#elif defined(BOTAN_HAS_SIMD_SCALAR)
  #include <botan/internal/simd_scalar.h>
   typedef SIMD_Scalar<uint,4> SIMD_32; }

#else
  #error "No SIMD module defined"

#endif

#endif
