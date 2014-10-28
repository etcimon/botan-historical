module botan.utils.simd.immintrin;

/*
* LDC, GDC, DMD Intrinsics for Intel AVX 2
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import core.simd;

alias __m256i = ubyte32;

pure:
nothrow:
@trusted:

version(GDC) {
	// GDC <--> immintrin => gcc/gcc/config/i386/immintrin.h
	static import gcc.attribute;
	import gcc.builtins;
	enum inline = gcc.attribute.attribute("forceinline");
	enum avx2 = gcc.attribute.attribute("target", "avx2");

	@inline
	int _rdrand32_step(uint* i) {
		return __builtin_ia32_rdrand32_step(i);
	}

	@inline @avx2
	__m256i _mm256_unpacklo_epi64(__m256i a, __m256i b) {
		return cast(__m256i) __builtin_ia32_punpcklqdq256(cast(long4) a, cast(long4) b);
	}


	@inline @avx2
	__m256i _mm256_unpackhi_epi64(__m256i a, __m256i b) {
		return cast(__m256i) __builtin_ia32_punpckhqdq256(cast(long4) a, cast(long4) b);
	}

	@inline @avx2
	__m256i _mm256_set_epi64x(long a, long b, long c, long d) {
		return cast(__m256i) long4(a, b, c, d);
	}
	
	@inline @avx2
	void _mm256_storeu_si256(__m256i* ptr, __m256i a) {
		__builtin_ia32_storedqu256(ptr, a);
		return;
	}

	@inline @avx2
	__m256i _mm256_loadu_si256(__m256i* ptr) {
		return cast(__m256i) __builtin_ia32_loaddqu256(ptr);
	}


	@inline @avx2
	__m256i _mm256_permute4x64_epi64(__m256 X, in int M) {
		return cast(__m256i) __builtin_ia32_permdi256(cast(long4) X, M);
	}

	@inline @avx2
	__m256i _mm256_add_epi64(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_paddq256(cast(long4) a, cast(long4) b);
	}
	
	@inline @avx2
	__m256i _mm256_sub_epi64(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_psubq256(cast(long4) a, cast(long4) b);
	}

	@inline @avx2
	__m256i _mm256_xor_si256(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_pxor256(cast(long4) a, cast(long4) b);
	}

	@inline @avx2
	__m256i _mm256_or_si256(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_por256(cast(long4) a, cast(long4) b);
	}

	@inline @avx2
	__m256i _mm256_srlv_epi64(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_psrlv4di(cast(long4) a, cast(long4) b);
	}

	@inline @avx2
	__m256i _mm256_sllv_epi64(__m256 a, __m256 b) {
		return cast(__m256i) __builtin_ia32_psllv4di(cast(long4) a, cast(long4) b);
	}


}

version(LDC) {
	// LDC <--> immintrin ==> clang/test/CodeGen/avx2-builtins.c, rdrand-builtins.c

	pragma(LDC_inline_ir)
		R inlineIR(string s, R, P...)(P);

	pragma(LDC_intrinsic, "llvm.x86.rdrand.32")
		int _rdrand32_step(uint*);

	__m256i _mm256_set_epi64x(long a, long b, long c, long d) {
		return cast(__m256i) long4(a, b, c, d);
	}

	__m256i _mm256_unpacklo_epi64(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`
			%tmp = shufflevector <4 x i64> %0, <4 x i64> %1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
			ret <4 x i64> %tmp`, 
		      __m256i)(a, b);
	}

	__m256i _mm256_unpackhi_epi64(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`
			%tmp = shufflevector <4 x i64> %0, <4 x i64> %1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
			ret <4 x i64> %tmp`,
				__m256i)(a, b);
	}
	
	__m256i _mm256_loadu_si256(__m256i* a) {
		pragma(LDC_allow_inline);
		return inlineIR!(`
			%tmp = load <4 x i64>* %0, align 1
			ret <4 x i64> %tmp`,
		                 __m256i)(a);
		
	}
	
	void _mm256_storeu_si256(__m256i* ptr, __m256i a) {
		pragma(LDC_allow_inline);
		return inlineIR!(`store <4 x i64> %1, <4 x i64>* %0
		       			  ret`,
		                 void)(ptr, a);
		
	}
	
	__m256i _mm256_permute4x64_epi64(__m256i a) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = shufflevector %0 <i32 3, i32 0, i32 2, i32 0>
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a);		
	}
	
	__m256i _mm256_add_epi64(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = add <4 x i64> %0, %1
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a, b);
	}

	__m256i _mm256_sub_epi64(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = sub <4 x i64> %0, %1
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a, b);
	}
		
	__m256i _mm256_xor_si256(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = xor <4 x i64> %0, %1
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a, b);
	}
	
	__m256i _mm256_or_si256(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = or <4 x i64> %0, %1
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a, b);
	}

	__m256i _mm256_or_si256(__m256i a, __m256i b) {
		pragma(LDC_allow_inline);
		return inlineIR!(`%tmp = or <4 x i64> %0, %1
		       			  ret <4 x i64> %tmp`,
		                 __m256i)(a, b);
	}

	pragma(LDC_intrinsic, "llvm.x86.avx2.psrlv.q.256")
		__m256i _mm256_srlv_epi64(__m256i a, __m256i b);

	pragma(LDC_intrinsic, "llvm.x86.avx2.psllv.q.256")
		__m256i _mm256_srlv_epi64(__m256i a, __m256i b);


}

version(DMD) {
	void store(__m128i* src, __m128i* dst) {
		asm
		{
			mov RAX, src;
			mov RBX, dst;
			movdqu XMM0, [RAX];
			movdqu [RBX], XMM0;
		}
	}
}

// _mm256_unpacklo_epi64
// _mm256_unpackhi_epi64
// _mm256_set_epi64x
// _mm256_loadu_si256
// _mm256_permute4x64_epi64
// _mm256_add_epi64
// _mm256_sub_epi64
// _mm256_xor_si256
// _mm256_or_si256
// _mm256_srlv_epi64
// _mm256_sllv_epi64
// _rdrand32_step => asm(".ubyte 0x0F, 0xC7, 0xF0; adcl $0,%1" : "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");