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
	import core.bitop : bswap;
	return bswap(val);
}

/**
* Swap a 64 bit integer
*/
ulong reverse_bytes(ulong val)
{
	static if (is(typeof(bswap64)))
		return bswap64(val);
	else {
		union { ulong u64; uint[2] u32; } input, output;
		input.u64 = val;
		output.u32[0] = reverse_bytes(input.u32[1]);
		output.u32[1] = reverse_bytes(input.u32[0]);
		return output.u64;
	}
}

/**
* Swap 4 Ts in an array
*/
void bswap_4(T)(ref T[4] x)
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
	void bswap_4(ref uint[4] x)
	{
		__m128i T = _mm_loadu_si128(cast(const(__m128i)*)(x.ptr));

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		T =  _mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8));

		_mm_storeu_si128(cast(__m128i*)(x.ptr), T);
	}
}