/*
* Byte Swapping Operations
* (C) 1999-2008 Jack Lloyd
* (C) 2007 Yves Jerschow
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BYTE_SWAP_H__
#define BOTAN_BYTE_SWAP_H__

#include <botan/types.h>
#include <botan/rotate.h>

#if defined(BOTAN_TARGET_CPU_HAS_SSE2)
  #include <emmintrin.h>
#endif

#if defined(BOTAN_TARGET_CPU_HAS_SSSE3)
  #include <tmmintrin.h>
#endif

namespace Botan {

/*
* Byte Swapping Functions
*/
inline u16bit reverse_bytes(u16bit input)
   {
   return rotate_left(input, 8);
   }

inline u32bit reverse_bytes(u32bit input)
   {
#if BOTAN_USE_GCC_INLINE_ASM && (defined(BOTAN_TARGET_ARCH_IS_IA32) || \
                                 defined(BOTAN_TARGET_ARCH_IS_AMD64))

   // GCC-style inline assembly for x86 or x86-64
   asm("bswapl %0" : "=r" (input) : "0" (input));
   return input;

#elif defined(_MSC_VER) && defined(BOTAN_TARGET_ARCH_IS_IA32)
   // Visual C++ inline asm for 32-bit x86, by Yves Jerschow
   __asm mov eax, input;
   __asm bswap eax;

#else
   // Generic implementation
   return (rotate_right(input, 8) & 0xFF00FF00) |
          (rotate_left (input, 8) & 0x00FF00FF);
#endif
   }

inline u64bit reverse_bytes(u64bit input)
   {
#if BOTAN_USE_GCC_INLINE_ASM && defined(BOTAN_TARGET_ARCH_IS_AMD64)
   // GCC-style inline assembly for x86-64
   asm("bswapq %0" : "=r" (input) : "0" (input));
   return input;

#else
   /* Generic implementation. Defined in terms of 32-bit bswap so any
    * optimizations in that version can help here (particularly
    * useful for 32-bit x86).
    */

   u32bit hi = static_cast<u32bit>(input >> 32);
   u32bit lo = static_cast<u32bit>(input);

   hi = reverse_bytes(hi);
   lo = reverse_bytes(lo);

   return (static_cast<u64bit>(lo) << 32) | hi;
#endif
   }

template<typename T>
inline void bswap_4(T x[4])
   {
   x[0] = reverse_bytes(x[0]);
   x[1] = reverse_bytes(x[1]);
   x[2] = reverse_bytes(x[2]);
   x[3] = reverse_bytes(x[3]);
   }

#if defined(BOTAN_TARGET_CPU_HAS_SSSE3)

template<>
inline void bswap_4(u32bit x[4])
   {
   const __m128i bswap_mask = _mm_set_epi8(
      12, 13, 14, 15,
       8,  9, 10, 11,
       4,  5,  6,  7,
       0,  1,  2,  3);

   __m128i T = _mm_loadu_si128((const __m128i*)x);
   T = _mm_shuffle_epi8(T, bswap_mask);
   _mm_storeu_si128((__m128i*)x, T);
   }

#elif defined(BOTAN_TARGET_CPU_HAS_SSE2)

template<>
inline void bswap_4(u32bit x[4])
   {
   __m128i T = _mm_loadu_si128((const __m128i*)x);

   T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
   T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

   T =  _mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8));

   _mm_storeu_si128((__m128i*)x, T);
   }

#endif

}

#endif
