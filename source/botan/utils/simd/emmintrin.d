module botan.utils.simd.emmintrin;

/*
* LDC, GDC, DMD Intrinsics for SSE 2
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2):
import core.simd;

pure:
nothrow:
@trusted:

alias __m128i = byte16;
alias __m64 = ulong;

int _MM_SHUFFLE(int a, int b, int c, int d)
{
    return (z<<6) | (y<<4) | (x<<2) | w;
}

// _mm_set1_epi32
__m128i _mm_set1_epi32 (int i)() {
    int4 vec = [i, i, i, i];
    return *cast(__m128i*) &vec;
}

// _mm_set1_epi32
__m128i _mm_set1_epi32 (int i) {
    int4 vec = [i, i, i, i];
    return *cast(__m128i*) &vec;
}

// _mm_set_epi32
immutable(__m128i) _mm_set_epi32 (int i, int j, int k, int l)() {
    int4 vec = [i, j, k, l];
    return *cast(immutable(__m128i)*) &vec;
}

// _mm_set_epi32
immutable(__m128i) _mm_set_epi32 (int i, int j, int k, int l) {
    int4 vec = [i, j, k, l];
    return *cast(immutable(__m128i)*) &vec;
}

// _mm_set_epi8
immutable(__m128i) _mm_set1_epi8 (byte i)() {
    return byte16([i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i]);
}

// _mm_set_epi8
immutable(__m128i) _mm_set1_epi8(byte[] arr)() {
    byte16 b16 = byte16(arr);
    return *cast(__m128i*) &b16;
}

// _mm_set1_epi16
__m128i _mm_set1_epi16(short w)() {
    short8 vec = short8([w,w,w,w,w,w,w,w]);
    return *cast(__m128i*) &vec;
}

version(GDC) {
    // GDC <--> emmintrin => gcc/gcc/config/i386/emmintrin.h
    static import gcc.attribute;
    import gcc.builtins;
    enum inline = gcc.attribute.attribute("forceinline");
@inline:
    // _mm_set1_epi16
    __m128i _mm_set1_epi16(short w) {
        short[8] a = [w,w,w,w,w,w,w,w];
        __m128i b;
        short[8]* _a = &a;
        __m128i* _b = &b;
        mixin( q{
            asm {
                "movdqu (%0), %xmm0\n"
                "movdqu %xmm0, (%1)\n"
                : : "0" (_a), "1" (_b) : "xmm0"
            }
        });
        return b;
    }

    ulong bswap64(ulong val) {
        return cast(ulong) __builtin_bswap64(val);
    }

    int _mm_cvtsi128_si32(__m128i a) {
        return cast(int) __builtin_ia32_vec_ext_v4si(cast(int4) a, 0);
    }

    // _mm_min_epu8
    __m128i _mm_min_epu8(__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pminub128(a, b);
    }

    __m128i _mm_shuffle_epi8(__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }

    // _mm_subs_epu16
    __m128i _mm_subs_epu16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubusw128(cast(short8) a, cast(short8) b);
    }

    // _mm_mulhi_epu16 ; PMULHUW
    __m128i _mm_mulhi_epu16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pmulhuw128(cast(short8) a, cast(short8) b);
    }


    // _mm_cmpeq_epi16 ; PCMPEQW
    __m128i _mm_cmpeq_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pcmpeqw128(cast(short8) a, cast(short8) b);
    }

    // _mm_mullo_epi16 ; PMULLW
    __m128i _mm_mullo_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pmullw128(cast(short8) a, cast(short8) b);
    }

    // _mm_sub_epi16 ; PSUBW
    __m128i _mm_sub_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubw128(cast(short8) a, cast(short8) b);
    }

    // _mm_add_epi16 ; PADDW
    __m128i _mm_add_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_paddw128(cast(short8) a, cast(short8) b);
    }

    // _mm_srli_epi16 ; PSRLW
    __m128i _mm_srli_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psrlwi128(cast(short8) a, imm);
    }

    // _mm_slli_epi16 ; PSLLW
    __m128i _mm_slli_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psllwi128(cast(short8) a, imm);
    }

    // _mm_shufflehi_epi16 ; PSHUFHW
    __m128i _mm_shufflehi_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshufhw(cast(short8) a, imm);
    }

    // _mm_shufflelo_epi16 ; PSHUFLW
    __m128i _mm_shufflelo_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshuflw(cast(short8) a, imm);
    }

    // _mm_add_epi32 ; PADDD
    __m128i _mm_add_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_paddd128(cast(int4) a, cast(int4) b);
    }

    // _mm_sub_epi32 ; PSUBD
    __m128i _mm_sub_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubd128(cast(int4) a, cast(int4) b);
    }

    // _mm_cmplt_epi32 ; PCMPGTDr
    __m128i _mm_cmplt_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pcmpgtd128(cast(int4) b, cast(int4) a);
    }

    // _mm_shuffle_epi32
    __m128i _mm_shuffle_epi32 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshufd(cast(int4) a, imm);
    }

    // _mm_extract_epi32 ; pextrd
    int _mm_extract_epi32(__m128i a, in int ndx) {
        return cast(__m128i) __builtin_ia32_vec_ext_v4si(cast(int4) a, ndx);
    }

    // _mm_unpackhi_epi32 ; PUNPCKHDQ
    __m128i _mm_unpackhi_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckhdq128(cast(int4) a, cast(int4) b);
    }

    // _mm_unpacklo_epi32 ; PUNPCKLDQ
    __m128i _mm_unpacklo_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckldq128(cast(int4) a, cast(int4) b);
    }

    // _mm_unpackhi_epi64 ; PUNPCKHQDQ
    __m128i _mm_unpackhi_epi64 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckhqdq128(cast(long2) a, cast(long2) b);
    }

    // _mm_unpacklo_epi64 ; PUNPCKLQDQ
    __m128i _mm_unpacklo_epi64 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpcklqdq128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_setzero_si128 ; PXOR
    __m128i _mm_setzero_si128 () {
        return cast(__m128i) int4([0, 0, 0, 0]);
    }

    // _mm_loadu_si128 ; MOVDQU
    __m128i _mm_loadu_si128 (in __m128i* p) {
        return cast(__m128i) __builtin_ia32_loaddqu(p);
    }

    // _mm_storeu_si128 ; MOVDQU
    void _mm_storeu_si128 (__m128i* p, in __m128i a) {
        return cast(__m128i) __builtin_ia32_storedqu(p, a);
    }

    // _mm_or_si128 ; POR
    __m128i _mm_or_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_por128(cast(long2) a, cast(long2) b);
    }

    // _mm_andnot_si128 ; PANDN
    __m128i _mm_andnot_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pandn128(cast(long2) a, cast(long2) b);
    }

    // _mm_and_si128 ; PAND
    __m128i _mm_and_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pand128(cast(long2) a, cast(long2) b);
    }

    // _mm_xor_si128 ; PXOR
    __m128i _mm_xor_si128 ( __m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pxor128(cast(long2) a, cast(long2) b);
    }

    // _mm_srli_si128 ; PSRLDQ
    __m128i _mm_srli_si128 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psrldqi128(a, imm*8);
    }

    // _mm_slli_si128 ; PSLLDQ
    __m128i _mm_slli_si128 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pslldqi128(a, imm*8);
    }
}

version(LDC) {
    import ldc.gccbuiltins_x86;

    pragma(LDC_intrinsic, "llvm.bswap.i64")
        ulong bswap64(ulong i);

    __m128i _mm_set1_epi16(short w) {
        short[8] a = [w,w,w,w,w,w,w,w];
        __m128i b;
        short[8]* _a = &a;
        __m128i* _b = &b;
        mixin( q{
            __asm {
                "movdqu (%0), %xmm0\n"
                ~ "movdqu %xmm0, (%1)\n"
                : : "0" (_a), "1" (_b) : "xmm0"
            }
        });
        return b;
    }

    int _mm_cvtsi128_si32(__m128i a) {
        return cast(int) __builtin_ia32_vec_ext_v4si(cast(int4) a, 0);
    }

    // _mm_shuffle_epi8
    __m128i _mm_shuffle_epi8(__m128i a, __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }

    // _mm_min_epu8
    __m128i _mm_min_epu8(__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pminub128(a, b);
    }
    
    // _mm_subs_epu16
    __m128i _mm_subs_epu16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubusw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_mulhi_epu16 ; PMULHUW
    __m128i _mm_mulhi_epu16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pmulhuw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_set1_epi16
    __m128i _mm_set1_epi16 (short w) {
        return cast(__m128i) short8([w,w,w,w,w,w,w,w]);
    }
    
    // _mm_cmpeq_epi16 ; PCMPEQW
    __m128i _mm_cmpeq_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pcmpeqw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_mullo_epi16 ; PMULLW
    __m128i _mm_mullo_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pmullw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_sub_epi16 ; PSUBW
    __m128i _mm_sub_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_add_epi16 ; PADDW
    __m128i _mm_add_epi16 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_paddw128(cast(short8) a, cast(short8) b);
    }
    
    // _mm_srli_epi16 ; PSRLW
    __m128i _mm_srli_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psrlwi128(cast(short8) a, imm);
    }
    
    // _mm_slli_epi16 ; PSLLW
    __m128i _mm_slli_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psllwi128(cast(short8) a, imm);
    }
    
    // _mm_shufflehi_epi16 ; PSHUFHW
    __m128i _mm_shufflehi_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshufhw(cast(short8) a, imm);
    }
    
    // _mm_shufflelo_epi16 ; PSHUFLW
    __m128i _mm_shufflelo_epi16 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshuflw(cast(short8) a, imm);
    }
    
    // _mm_add_epi32 ; PADDD
    __m128i _mm_add_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_paddd128(cast(int4) a, cast(int4) b);
    }
    
    // _mm_sub_epi32 ; PSUBD
    __m128i _mm_sub_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_psubd128(cast(int4) a, cast(int4) b);
    }
    
    // _mm_cmplt_epi32 ; PCMPGTDr
    __m128i _mm_cmplt_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pcmpgtd128(cast(int4) b, cast(int4) a);
    }

    // _mm_shuffle_epi32
    __m128i _mm_shuffle_epi32 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pshufd(cast(int4) a, imm);
    }
    
    // _mm_extract_epi32 ; pextrd
    int _mm_extract_epi32(__m128i a, in int ndx) {
        return cast(__m128i) __builtin_ia32_vec_ext_v4si(cast(int4) a, ndx);
    }
    
    // _mm_unpackhi_epi32 ; PUNPCKHDQ
    __m128i _mm_unpackhi_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckhdq128(cast(int4) a, cast(int4) b);
    }
    
    // _mm_unpacklo_epi32 ; PUNPCKLDQ
    __m128i _mm_unpacklo_epi32 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckldq128(cast(int4) a, cast(int4) b);
    }
    
    // _mm_unpackhi_epi64 ; PUNPCKHQDQ
    __m128i _mm_unpackhi_epi64 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpckhqdq128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_unpacklo_epi64 ; PUNPCKLQDQ
    __m128i _mm_unpacklo_epi64 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_punpcklqdq128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_setzero_si128 ; PXOR
    __m128i _mm_setzero_si128 () {
        return cast(__m128i) int4([0, 0, 0, 0]);
    }
    
    // _mm_loadu_si128 ; MOVDQU
    __m128i _mm_loadu_si128 (in __m128i* p) {
        return cast(__m128i) __builtin_ia32_loaddqu(p);
    }
    
    // _mm_storeu_si128 ; MOVDQU
    void _mm_storeu_si128 (in __m128i *p, in __m128i a) {
        return cast(__m128i) __builtin_ia32_storedqu(p, a);
    }
    
    // _mm_or_si128 ; POR
    __m128i _mm_or_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_por128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_andnot_si128 ; PANDN
    __m128i _mm_andnot_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pandn128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_and_si128 ; PAND
    __m128i _mm_and_si128 (__m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pand128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_xor_si128 ; PXOR
    __m128i _mm_xor_si128 ( __m128i a, in __m128i b) {
        return cast(__m128i) __builtin_ia32_pxor128(cast(long2) a, cast(long2) b);
    }
    
    // _mm_srli_si128 ; PSRLDQ
    __m128i _mm_srli_si128 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_psrldqi128(a, imm*8);
    }
    
    // _mm_slli_si128 ; PSLLDQ
    __m128i _mm_slli_si128 (__m128i a, in int imm) {
        return cast(__m128i) __builtin_ia32_pslldqi128(a, imm*8);
    }
    
    // bswap64
    
}

version(D_InlineAsm_X86_64) {
    // _mm_set1_epi16
    __m128i _mm_set1_epi16(short w) {
        short[8] a = [w,w,w,w,w,w,w,w];
        __m128i b;
        short[8]* _a = &a;
        __m128i* _b = &b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu [RBX], XMM0;
        }
        return b;
    }

    int _mm_cvtsi128_si32(__m128i a) {
        int ret;
        int* _ret = &ret;
        const(__m128i)* _a = &a;
        asm {
            mov RAX, _a;
            mov RBX, _ret;
            movdqu XMM0, [RAX];
            movd [RBX], XMM0;
        }
        return ret;
    }

    // _mm_min_epu8 ; PMINUB
    __m128i _mm_min_epu8(__m128i a, in __m128i b) {

        __m128i* _a = &a;
        const(__m128i)* _b = &b;

        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pminub XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }

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

    // _mm_subs_epu16 ; PSUBUSW
    __m128i _mm_subs_epu16 (__m128i a, in __m128i b) {

        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            psubusw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_mulhi_epu16 ; PMULHUW
    __m128i _mm_mulhi_epu16 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pmulhuw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
        
    // _mm_cmpeq_epi16 ; PCMPEQW
    __m128i _mm_cmpeq_epi16 (__m128i a, in __m128i b) {

        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pcmpeqw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_mullo_epi16 ; PMULLW
    __m128i _mm_mullo_epi16 (__m128i a, in __m128i b) {

        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pmullw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;

    }
    
    // _mm_sub_epi16 ; PSUBW
    __m128i _mm_sub_epi16 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            psubw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_add_epi16 ; PADDW
    __m128i _mm_add_epi16 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            paddw XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }

    // _mm_srli_epi16 ; PSRLW
    __m128i _mm_srli_epi16 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            psrlw XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }    

    // _mm_srli_epi32 ; PSRLD
    __m128i _mm_srli_epi32 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            psrld XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }

    // _mm_slli_epi32 ; PSLLD
    __m128i _mm_slli_epi32 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pslld XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_slli_epi16 ; PSLLW
    __m128i _mm_slli_epi16(__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            psllw XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_shufflehi_epi16 ; PSHUFHW
    __m128i _mm_shufflehi_epi16 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pshufhw XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_shufflelo_epi16 ; PSHUFLW
    __m128i _mm_shufflelo_epi16 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pshuflw XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_add_epi32 ; PADDD
    __m128i _mm_add_epi32 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            paddd XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_sub_epi32 ; PSUBD
    __m128i _mm_sub_epi32 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            psubd XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_cmplt_epi32 ; PCMPGTD
    __m128i _mm_cmplt_epi32 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pcmpgtd XMM0, XMM1;
            movdqu [RAX], XMM0;
        }

        return a;
    }

    // _mm_shuffle_epi32 ;  PSHUFD
    __m128i _mm_shuffle_epi32 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pshufd XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_extract_epi32 ; pextrd
    int _mm_extract_epi32(__m128i a, in int ndx) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) ndx;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pextrd XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_unpackhi_epi32 ; PUNPCKHDQ
    __m128i _mm_unpackhi_epi32 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            punpckhdq XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_unpacklo_epi32 ; PUNPCKLDQ
    __m128i _mm_unpacklo_epi32 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            punpckldq XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_unpackhi_epi64 ; PUNPCKHQDQ
    __m128i _mm_unpackhi_epi64 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            punpckhqdq XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_unpacklo_epi64 ; PUNPCKLQDQ
    __m128i _mm_unpacklo_epi64 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            punpcklqdq XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_setzero_si128 ; PXOR
    __m128i _mm_setzero_si128 () {
        return cast(__m128i) int4([0, 0, 0, 0]);
    }
    
    // _mm_loadu_si128 ; MOVDQU
    __m128i _mm_loadu_si128 (in __m128i* p) {
        __m128i a;
        __m128i* _a = &a;
        
        asm {
            mov RAX, p;
            mov RBX, _a;
            movdqu XMM0, [RAX];
            movdqu [RBX], XMM0;
        }
        
        return a;
    }
    
    // _mm_storeu_si128 ; MOVDQU
    void _mm_storeu_si128 (in __m128i* p, in __m128i a) {
        __m128i* _a = &a;
        
        asm {
            mov RAX, _a;
            mov RBX, p;
            movdqu XMM0, [RAX];
            movdqu [RBX], XMM0;
            ret;
        }
    }
    
    // _mm_or_si128 ; POR
    __m128i _mm_or_si128 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            por XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_andnot_si128 ; PANDN
    __m128i _mm_andnot_si128 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pandn XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_and_si128 ; PAND
    __m128i _mm_and_si128 (__m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pand XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_xor_si128 ; PXOR
    __m128i _mm_xor_si128 ( __m128i a, in __m128i b) {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            movdqu XMM1, [RBX];
            pxor XMM0, XMM1;
            movdqu [RAX], XMM0;
        }
        
        return a;
    }
    
    // _mm_srli_si128 ; PSRLDQ
    __m128i _mm_srli_si128 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            psrldq XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
    
    // _mm_slli_si128 ; PSLLDQ
    __m128i _mm_slli_si128 (__m128i a, in int imm) {
        __m128i* _a = &a;
        const(byte) b = cast(const byte) imm;
        const(byte)* _b = cast(const(byte)*)&b;
        asm {
            mov RAX, _a;
            mov RBX, _b;
            movdqu XMM0, [RAX];
            pslldq XMM0, [RBX];
            movdqu [RAX], XMM0;
        }
        return a;
    }
}