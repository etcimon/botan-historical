module botan.utils.simd.tmmintrin;
/*
* LDC, GDC, DMD Intrinsics for SSSE 3
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import botan.constants;
static if (BOTAN_HAS_AES_SSSE3 && BOTAN_HAS_SIMD_SSE2):

public import botan.utils.simd.emmintrin;


version(GDC) {
@inline:
    // _mm_shuffle_epi8
    __m128i _mm_shuffle_epi8(__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }
}

version(LDC) {    
    // _mm_shuffle_epi8
    __m128i _mm_shuffle_epi8(__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }
}

version(D_InlineAsm_X86_64) {
    // _mm_min_epi8 ; PSHUFB
    __m128i _mm_shuffle_epi8(__m128i a, in __m128i b) {
        
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pshufb XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
}