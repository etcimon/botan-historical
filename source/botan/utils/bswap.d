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
ushort reverseBytes(ushort val)
{
    return rotateLeft(val, 8);
}

/**
* Swap a 32 bit integer
*/
uint reverseBytes(uint val)
{
    import core.bitop : bswap;
    return bswap(val);
}

/**
* Swap a 64 bit integer
*/
ulong reverseBytes(ulong val)
{
    static if (is(typeof(bswap64)))
        return bswap64(val);
    else {
        union { ulong u64; uint[2] u32; } input, output;
        input.u64 = val;
        output.u32[0] = reverseBytes(input.u32[1]);
        output.u32[1] = reverseBytes(input.u32[0]);
        return output.u64;
    }
}

/**
* Swap 4 Ts in an array
*/
void bswap4(T)(ref T[4] x)
{
    x[0] = reverseBytes(x[0]);
    x[1] = reverseBytes(x[1]);
    x[2] = reverseBytes(x[2]);
    x[3] = reverseBytes(x[3]);
}

static if (BOTAN_TARGET_CPU_HAS_SSE2 && !BOTAN_NO_SSE_INTRINSICS) {

    /**
    * Swap 4 uints in an array using SSE2 shuffle instructions
    */
    void bswap4(ref uint[4] x)
    {
        __m128i T = _mm_loadu_si128(cast(const(__m128i)*)(x.ptr));

        T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
        T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

        T =  _mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8));

        _mm_storeu_si128(cast(m128i*)(x.ptr), T);
    }
}