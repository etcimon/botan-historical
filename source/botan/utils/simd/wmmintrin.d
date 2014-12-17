module botan.utils.simd.wmmintrin;
/*
* LDC, GDC, DMD Intrinsics for SSSE 3
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2):

public import botan.utils.simd.emmintrin;
pure:
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

version(D_Version2) {
    __m128i _mm_aesenc_si128 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            aesenc XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }

    __m128i _mm_aesenclast_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            aesenclast XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    __m128i _mm_aesdec_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            aesdec XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }


    __m128i _mm_aesdeclast_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            aesdeclast XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }

    __m128i _mm_aesimc_si128(__m128i a) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            aesimc XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }

    __m128i _mm_aeskeygenassist_si128(__m128i a, in int b) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            aeskeygenassist XMM1, XMM0, [RBX];
            movdqu [RAX], XMM1;
        }
        
        return a;
    }
    
    __m128i _mm_clmulepi64_si128(__m128i a, __m128i b, in int imm) {
        /// todo: Enable this after adding PCLMULQDQ in dmd
        assert(false, "PCLMULQDQ not supported yet in DMD");
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        const(byte) c = cast(const byte) imm;
        const(byte)* _c = cast(const(byte)*)&c;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            mov RCX, _c;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            // pclmulqdq XMM0, XMM1, [RCX];
            movdqu [RAX], XMM0;
        }
        
        return a;
    }


}