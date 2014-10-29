module botan.utils.simd.wmmintrin;
/*
* LDC, GDC, DMD Intrinsics for SSSE 3
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import botan.constants;
static if (BOTAN_HAS_AES_SSSE3):

public import botan.utils.simd.emmintrin;

// _mm_aesenc_si128
// _mm_aesenclast_si128
// _mm_aesdec_si128
// _mm_aesdeclast_si128
// _mm_aesimc_si128
// _mm_aeskeygenassist_si128

version(GDC) {
@inline:
	// _mm_aesenc_si128
	__m128i _mm_aesenc_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesenc128(cast(long2) a, cast(long2) b);
	}

	__m128i _mm_aesenclast_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesenclast128(cast(long2) a, cast(long2) b);
	}

	__m128i _mm_aesdec_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesdec128(cast(long2) a, cast(long2) b);
	}

	__m128i _mm_aesdeclast_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesdeclast128(cast(long2) a, cast(long2) b);
	}

	__m128i _mm_aesimc_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesimc128(cast(long2) a, cast(long2) b);
	}

	__m128i _mm_aeskeygenassist_si128(__m128i a, in int b) {
		return cast(__m128i) __builtin_ia32_aeskeygenassist128(cast(long2) a, b);
	}

	__m128i _mm_clmulepi64_si128(__m128i a, __m128i b, in int c) {
		return cast(__m128i) __builtin_ia32_pclmulqdq128(cast(long2) a, cast(long2) b, c);
	}
}

version(LDC) {
	// _mm_aesenc_si128
	__m128i _mm_aesenc_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesenc128(cast(long2) a, cast(long2) b);
	}
	
	__m128i _mm_aesenclast_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesenclast128(cast(long2) a, cast(long2) b);
	}
	
	__m128i _mm_aesdec_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesdec128(cast(long2) a, cast(long2) b);
	}
	
	__m128i _mm_aesdeclast_si128(__m128i a, in __m128i b) {
		return cast(__m128i) __builtin_ia32_aesdeclast128(cast(long2) a, cast(long2) b);
	}
	
	__m128i _mm_aesimc_si128(__m128i a) {
		return cast(__m128i) __builtin_ia32_aesimc128(cast(long2) a);
	}

	__m128i _mm_aeskeygenassist_si128(__m128i a, in int b) {
		return cast(__m128i) __builtin_ia32_aeskeygenassist128(cast(long2) a, b);
	}

	__m128i _mm_clmulepi64_si128(__m128i a, __m128i b, in int c) {
		return cast(__m128i) __builtin_ia32_pclmulqdq128(cast(long2) a, cast(long2) b, c);
	}
}

version(DMD) {

}