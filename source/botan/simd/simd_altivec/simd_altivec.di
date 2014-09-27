/*
* Lightweight wrappers around AltiVec for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#if defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)

#include <botan/loadstor.h>
#include <botan/cpuid.h>

#include <altivec.h>
#undef vector
#undef bool
class SIMD_Altivec
{
	public:
		static bool enabled() { return CPUID::has_altivec(); }

		SIMD_Altivec(const uint B[4])
		{
			reg = (__vector uint){B[0], B[1], B[2], B[3]};
		}

		SIMD_Altivec(uint B0, uint B1, uint B2, uint B3)
		{
			reg = (__vector uint){B0, B1, B2, B3};
		}

		SIMD_Altivec(uint B)
		{
			reg = (__vector uint){B, B, B, B};
		}

		static SIMD_Altivec load_le(const void* input)
		{
			const uint* in_32 = cast(const uint*)(input);

			__vector uint R0 = vec_ld(0, in_32);
			__vector uint R1 = vec_ld(12, in_32);

			__vector char perm = vec_lvsl(0, in_32);

			perm = vec_xor(perm, vec_splat_u8(3));

			R0 = vec_perm(R0, R1, perm);

			return SIMD_Altivec(R0);
		}

		static SIMD_Altivec load_be(const void* input)
		{
			const uint* in_32 = cast(const uint*)(input);

			__vector uint R0 = vec_ld(0, in_32);
			__vector uint R1 = vec_ld(12, in_32);

			__vector char perm = vec_lvsl(0, in_32);

			R0 = vec_perm(R0, R1, perm);

			return SIMD_Altivec(R0);
		}

		void store_le(byte* output) const
		{
			__vector char perm = vec_lvsl(0, (uint*)0);

			perm = vec_xor(perm, vec_splat_u8(3));

			union {
				__vector uint V;
				uint R[4];
			} vec;

			vec.V = vec_perm(reg, reg, perm);

			Botan::store_be(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
		}

		void store_be(byte* output) const
		{
			union {
				__vector uint V;
				uint R[4];
			} vec;

			vec.V = reg;

			Botan::store_be(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
		}

		void rotate_left(size_t rot)
		{
			__vector uint rot_vec =
				(__vector uint){rot, rot, rot, rot};

			reg = vec_rl(reg, rot_vec);
		}

		void rotate_right(size_t rot)
		{
			rotate_left(32 - rot);
		}

		void operator+=(in SIMD_Altivec other)
		{
			reg = vec_add(reg, other.reg);
		}

		SIMD_Altivec operator+(in SIMD_Altivec other) const
		{
			return vec_add(reg, other.reg);
		}

		void operator-=(in SIMD_Altivec other)
		{
			reg = vec_sub(reg, other.reg);
		}

		SIMD_Altivec operator-(in SIMD_Altivec other) const
		{
			return vec_sub(reg, other.reg);
		}

		void operator^=(in SIMD_Altivec other)
		{
			reg = vec_xor(reg, other.reg);
		}

		SIMD_Altivec operator^(in SIMD_Altivec other) const
		{
			return vec_xor(reg, other.reg);
		}

		void operator|=(in SIMD_Altivec other)
		{
			reg = vec_or(reg, other.reg);
		}

		SIMD_Altivec operator&(in SIMD_Altivec other)
		{
			return vec_and(reg, other.reg);
		}

		void operator&=(in SIMD_Altivec other)
		{
			reg = vec_and(reg, other.reg);
		}

		SIMD_Altivec operator<<(size_t shift) const
		{
			__vector uint shift_vec =
				(__vector uint){shift, shift, shift, shift};

			return vec_sl(reg, shift_vec);
		}

		SIMD_Altivec operator>>(size_t shift) const
		{
			__vector uint shift_vec =
				(__vector uint){shift, shift, shift, shift};

			return vec_sr(reg, shift_vec);
		}

		SIMD_Altivec operator~() const
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
			__vector char perm = vec_lvsl(0, (uint*)0);

			perm = vec_xor(perm, vec_splat_u8(3));

			return SIMD_Altivec(vec_perm(reg, reg, perm));
		}

		static void transpose(SIMD_Altivec& B0, SIMD_Altivec& B1,
									 SIMD_Altivec& B2, SIMD_Altivec& B3)
		{
			__vector uint T0 = vec_mergeh(B0.reg, B2.reg);
			__vector uint T1 = vec_mergel(B0.reg, B2.reg);
			__vector uint T2 = vec_mergeh(B1.reg, B3.reg);
			__vector uint T3 = vec_mergel(B1.reg, B3.reg);

			B0.reg = vec_mergeh(T0, T2);
			B1.reg = vec_mergel(T0, T2);
			B2.reg = vec_mergeh(T1, T3);
			B3.reg = vec_mergel(T1, T3);
		}

	private:
		SIMD_Altivec(__vector uint input) { reg = input; }

		__vector uint reg;
};
#endif
