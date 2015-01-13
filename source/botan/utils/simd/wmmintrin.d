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

    __m128i _mm_aesimc_si128(__m128i a) {
        return cast(__m128i) __builtin_ia32_aesimc128(cast(long2) a);
    }

    __m128i _mm_aeskeygenassist_si128(int b)(__m128i a) {
        return cast(__m128i) __builtin_ia32_aeskeygenassist128(cast(long2) a, b);
    }

    __m128i _mm_clmulepi64_si128(int c)(__m128i a, __m128i b) {
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

    __m128i _mm_aeskeygenassist_si128(int b)(__m128i a) {
        return cast(__m128i) __builtin_ia32_aeskeygenassist128(cast(long2) a, b);
    }

    __m128i _mm_clmulepi64_si128(int c)(__m128i a, __m128i b) {
        return cast(__m128i) __builtin_ia32_pclmulqdq128(cast(long2) a, cast(long2) b, c);
    }
}

version(D_Version2) {
    __m128i _mm_aesenc_si128 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            aesenc XMM1, XMM2;
            movdqu [RAX], XMM1;
        }
        
        return a;
    }

    __m128i _mm_aesenclast_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            aesenclast XMM1, XMM2;
            movdqu [RAX], XMM1;
        }
        
        return a;
    }
    
    __m128i _mm_aesdec_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            aesdec XMM1, XMM2;
            movdqu [RAX], XMM1;
        }
        
        return a;
    }


    __m128i _mm_aesdeclast_si128(__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            aesdeclast XMM1, XMM2;
            movdqu [RAX], XMM1;
        }
        
        return a;
    }

    __m128i _mm_aesimc_si128(__m128i a) {
        __m128i* _a = &a;
        
        asm pure nothrow {
            mov RAX, _a;
            movdqu XMM2, [RAX];
            aesimc XMM1, XMM2;
            movdqu [RAX], XMM1;
        }
        
        return a;
    }

    __m128i _mm_aeskeygenassist_si128(int b)(__m128i a) {
        __m128i* _a = &a;
        
        mixin(`asm pure nothrow {
            mov RAX, _a;
            movdqu XMM1, [RAX];
            aeskeygenassist XMM2, XMM1, ` ~ b.to!string ~ `;
            movdqu [RAX], XMM2;
        }`);
        
        return a;
    }
    
    __m128i _mm_clmulepi64_si128(int imm)(__m128i a, __m128i b) {
        /// todo: Enable this after adding PCLMULQDQ in dmd
        __m128i* _a = &a;
		__m128i* _b = &b;
                
        mixin(`asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            db 0x660F3A44, 0xCA, ` ~ imm.to!ubyte.to!string ~ `;
            movdqu [RAX], XMM1;
        }`);
        
        return a;
    }


}