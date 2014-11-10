/*
* Lightweight wrappers around AltiVec for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_altivec;

// static if (BOTAN_TARGET_SUPPORTS_ALTIVEC):

import botan.utils.loadstor;
import botan.utils.cpuid;

//import altivec.h;

struct SIMD_Altivec
{
public:
	static bool enabled() { return CPUID.has_altivec(); }

	this(const uint B[4])
	{
		reg = [B[0], B[1], B[2], B[3]];
	}

	this(uint B0, uint B1, uint B2, uint B3)
	{
		reg = [B0, B1, B2, B3];
	}

	this(uint B)
	{
		reg = [B, B, B, B];
	}

	static SIMD_Altivec load_le(const void* input)
	{
		const uint* in_32 = cast(const uint*)(input);

		Vector!uint R0 = vec_ld(0, in_32);
		Vector!uint R1 = vec_ld(12, in_32);

		Vector!char perm = vec_lvsl(0, in_32);

		perm = vec_xor(perm, vec_splat_u8(3));

		R0 = vec_perm(R0, R1, perm);

		return SIMD_Altivec(R0);
	}

	static SIMD_Altivec load_be(const void* input)
	{
		const uint* in_32 = cast(const uint*)(input);

		Vector!uint R0 = vec_ld(0, in_32);
		Vector!uint R1 = vec_ld(12, in_32);

		Vector!char perm = vec_lvsl(0, in_32);

		R0 = vec_perm(R0, R1, perm);

		return SIMD_Altivec(R0);
	}

	void store_le(ubyte* output) const
	{
		Vector!char perm = vec_lvsl(0, (uint*)0);

		perm = vec_xor(perm, vec_splat_u8(3));

		union {
			Vector!uint V;
			uint R[4];
		} vec;

		vec.V = vec_perm(reg, reg, perm);

		store_be(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
	}

	void store_be(ubyte* output) const
	{
		union {
			Vector!uint V;
			uint R[4];
		} vec;

		vec.V = reg;

		store_be(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
	}

	void rotate_left(size_t rot)
	{
		Vector!uint rot_vec =
			(Vector!uint){rot, rot, rot, rot};

		reg = vec_rl(reg, rot_vec);
	}

	void rotate_right(size_t rot)
	{
		rotate_left(32 - rot);
	}

	void opOpAssign(string op)(in SIMD_Altivec other)
		if (op == "+=")
	{
		reg = vec_add(reg, other.reg);
	}

	SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
		if (op == "+")
	{
		return vec_add(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_Altivec other)
		if (op == "-=")
	{
		reg = vec_sub(reg, other.reg);
	}

	SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
		if (op == "-")
	{
		return vec_sub(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_Altivec other)
		if (op == "^=")
	{
		reg = vec_xor(reg, other.reg);
	}

	SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
		if (op == "^")
	{
		return vec_xor(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_Altivec other)
		if (op == "|=")
	{
		reg = vec_or(reg, other.reg);
	}

	SIMD_Altivec opBinary(string op)(in SIMD_Altivec other)
		if (op == "&")
	{
		return vec_and(reg, other.reg);
	}

	void opOpAssign(string op)(in SIMD_Altivec other)
		if (op == "&=")
	{
		reg = vec_and(reg, other.reg);
	}

	SIMD_Altivec opBinary(string op)(size_t shift) const
		if (op == "<<")
	{
		Vector!uint shift_vec =
			Vector!uint([shift, shift, shift, shift]);

		return vec_sl(reg, shift_vec);
	}

	SIMD_Altivec opBinary(string op)(size_t shift) const
		if (op == ">>")
	{
		Vector!uint shift_vec =
			Vector!uint([shift, shift, shift, shift]);

		return vec_sr(reg, shift_vec);
	}

	SIMD_Altivec opUnary(string op)() const
		if (op == "~")
	{
		return vec_nor(reg, reg);
	}

	SIMD_Altivec andc(in SIMD_Altivec other)
	{
		// AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
		return vec_andc(other.reg, reg);
	}

	SIMD_Altivec bswap() const
	{
		Vector!char perm = vec_lvsl(0, null);

		perm = vec_xor(perm, vec_splat_u8(3));

		return SIMD_Altivec(vec_perm(reg, reg, perm));
	}

	static void transpose(ref SIMD_Altivec B0, refSIMD_Altivec B1,
								 ref SIMD_Altivec B2, ref SIMD_Altivec B3)
	{
		Vector!uint T0 = vec_mergeh(B0.reg, B2.reg);
		Vector!uint T1 = vec_mergel(B0.reg, B2.reg);
		Vector!uint T2 = vec_mergeh(B1.reg, B3.reg);
		Vector!uint T3 = vec_mergel(B1.reg, B3.reg);

		B0.reg = vec_mergeh(T0, T2);
		B1.reg = vec_mergel(T0, T2);
		B2.reg = vec_mergeh(T1, T3);
		B3.reg = vec_mergel(T1, T3);
	}

private:
	this(Vector!uint input) { reg = input; }

	Vector!uint reg;
}
