/*
* Byte Swapping Operations
* (C) 1999-2011 Jack Lloyd
* (C) 2007 Yves Jerschow
*
* Distributed under the terms of the botan license.
*/
module botan.utils.bswap;

import botan.utils.types;
import botan.utils.rotate;

static if (BOTAN_TARGET_CPU_HAS_SSE2 && !BOTAN_NO_SSE_INTRINSICS) {
  import botan.utils.simd.emmintrin;
}
/**
* Swap a 16 bit integer
*/
ushort reverse_bytes(ushort val)
{
	return rotate_left(val, 8);
}

/**
* Swap a 32 bit integer
*/
uint reverse_bytes(uint val)
{
	static if (!BOTAN_TARGET_CPU_IS_ARM_FAMILY) {
		/*
		GCC intrinsic added in 4.3, works for a number of CPUs

		However avoid under ARM, as it branches to a function in libgcc
		instead of generating  asm, so slower even than the generic
		rotate version below.
		*/
		return __builtin_bswap32(val);

	} else static if (BOTAN_USE_GCC_INLINE_ASM && BOTAN_TARGET_CPU_IS_X86_FAMILY) {

		// GCC-style  assembly for x86 or x86-64
		/// todo asm("bswapl %0" : "=r" (val) : "0" (val));
		return val;

	} else static if (BOTAN_USE_GCC_INLINE_ASM && BOTAN_TARGET_CPU_IS_ARM_FAMILY) {

		/* todo asm ("eor r3, %1, %1, ror #16\t"
			  "bic r3, r3, #0x00FF0000\t"
			  "mov %0, %1, ror #8\t"
			  "eor %0, %0, r3, lsr #8"
			  : "=r" (val)
			  : "0" (val)
			  : "r3", "cc"); */

		return val;

	} else {
		// Generic implementation
		return (rotate_right(val, 8) & 0xFF00FF00) |
				 (rotate_left (val, 8) & 0x00FF00FF);

	}
}

/**
* Swap a 64 bit integer
*/
ulong reverse_bytes(ulong val)
{
	// GCC intrinsic added in 4.3, works for a number of CPUs
	return __builtin_bswap64(val);
}

/**
* Swap 4 Ts in an array
*/
void bswap_4(T)(T[4] x)
{
	x[0] = reverse_bytes(x[0]);
	x[1] = reverse_bytes(x[1]);
	x[2] = reverse_bytes(x[2]);
	x[3] = reverse_bytes(x[3]);
}

static if (BOTAN_TARGET_CPU_HAS_SSE2 && !BOTAN_NO_SSE_INTRINSICS) {

	/**
	* Swap 4 uints in an array using SSE2 shuffle instructions
	*/
	void bswap_4(uint[4] x)
	{
		__m128i T = _mm_loadu_si128(cast(const __m128i*)(x.ptr));

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		T =  _mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8));

		_mm_storeu_si128(cast(__m128i*)(x.ptr), T);
	}
}