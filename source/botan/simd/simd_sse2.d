/*
* Lightweight wrappers for SSE2 intrinsics for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_sse2;
//static if (BOTAN_TARGET_SUPPORTS_SSE2):

import botan.utils.cpuid;
import botan.utils.simd.emmintrin;

struct SIMD_SSE2
{
public:
	static bool enabled() { return CPUID.has_sse2(); }

	this(const uint[4]* B)
	{
		reg = _mm_loadu_si128(cast(const(__m128i)*)(B));
	}

	this(uint B0, uint B1, uint B2, uint B3)
	{
		reg = _mm_set_epi32!(B0, B1, B2, B3)();
	}

	this(uint B)
	{
		reg = _mm_set1_epi32!(B)();
	}

	static SIMD_SSE2 load_le(const void* input)
	{
		return _mm_loadu_si128(cast(const(__m128i)*)(input));
	}

	static SIMD_SSE2 load_be(in void* input)
	{
		return load_le(input).bswap();
	}

	void store_le(ubyte* output) const
	{
		_mm_storeu_si128(cast(__m128i*)(output), reg);
	}

	void store_be(ubyte* output) const
	{
		bswap().store_le(output);
	}

	void rotate_left(size_t rot)
	{
		reg = _mm_or_si128(_mm_slli_epi32(reg, cast(int)(rot)),
								 _mm_srli_epi32(reg, cast(int)(32-rot)));
	}

	void rotate_right(size_t rot)
	{
		rotate_left(32 - rot);
	}

	void opOpAssign(string op)(in SIMD_SSE2 other)
		if (op == "+=")
	{
		reg = _mm_add_epi32(reg, other.reg);
	}

	SIMD_SSE2 opBinary(string op)(in SIMD_SSE2 other) const
		if (op == "+")
	{
		return _mm_add_epi32(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_SSE2 other)
		if (op == "-=")
	{
		reg = _mm_sub_epi32(reg, other.reg);
	}

	SIMD_SSE2 opBinary(string op)(in SIMD_SSE2 other) const
		if (op == "-")
	{
		return _mm_sub_epi32(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_SSE2 other)
		if (op == "^=")
	{
		reg = _mm_xor_si128(reg, other.reg);
	}

	SIMD_SSE2 opBinary(string op)(in SIMD_SSE2 other) const
		if (op == "^")
	{
		return _mm_xor_si128(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_SSE2 other)
		if (op == "|=")
	{
		reg = _mm_or_si128(reg, other.reg);
	}

	SIMD_SSE2 opBinary(string op)(in SIMD_SSE2 other)
		if (op == "&")
	{
		return _mm_and_si128(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_SSE2 other)
		if (op == "&=")
	{
		reg = _mm_and_si128(reg, other.reg);
	}

	SIMD_SSE2 opBinary(string op)(size_t shift) const
		if (op == "<<")
	{
		return _mm_slli_epi32(reg, cast(int)(shift));
	}

	SIMD_SSE2 opBinary(string op)(size_t shift) const
		if (op == ">>")
	{
		return _mm_srli_epi32(reg, cast(int)(shift));
	}

	SIMD_SSE2 OpUnary(string op)() const
		if (op == "~")
	{
		return _mm_xor_si128(reg, _mm_set1_epi32!(0xFFFFFFFF)());
	}

	// (~reg) & other
	SIMD_SSE2 andc(in SIMD_SSE2 other)
	{
		return _mm_andnot_si128(reg, other.reg);
	}

	SIMD_SSE2 bswap() const
	{
		__m128i T = reg;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return _mm_or_si128(_mm_srli_epi16(T, 8),
								  _mm_slli_epi16(T, 8));
	}

	static void transpose(ref SIMD_SSE2 B0, ref SIMD_SSE2 B1,
								 ref SIMD_SSE2 B2, ref SIMD_SSE2 B3)
	{
		__m128i T0 = _mm_unpacklo_epi32(B0.reg, B1.reg);
		__m128i T1 = _mm_unpacklo_epi32(B2.reg, B3.reg);
		__m128i T2 = _mm_unpackhi_epi32(B0.reg, B1.reg);
		__m128i T3 = _mm_unpackhi_epi32(B2.reg, B3.reg);
		B0.reg = _mm_unpacklo_epi64(T0, T1);
		B1.reg = _mm_unpackhi_epi64(T0, T1);
		B2.reg = _mm_unpacklo_epi64(T2, T3);
		B3.reg = _mm_unpackhi_epi64(T2, T3);
	}

private:
	this(__m128i input) { reg = input; }

	__m128i reg;
}