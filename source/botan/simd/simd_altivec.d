/*
* Lightweight wrappers around AltiVec for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_altivec;

static if (BOTAN_TARGET_SUPPORTS_ALTIVEC):

import botan.utils.loadstor;
import botan.utils.cpuid;

import botan.utils.simd.altivec;

struct SIMD_Altivec
{
public:
    static bool enabled() { return CPUID.has_altivec(); }

    this(in uint[4] B)
    {
        m_reg = [B[0], B[1], B[2], B[3]];
    }

    this(uint B0, uint B1, uint B2, uint B3)
    {
        m_reg = [B0, B1, B2, B3];
    }

    this(uint B)
    {
        m_reg = [B, B, B, B];
    }

    static SIMD_Altivec load_littleEndian(in void* input)
    {
        const uint* in_32 = cast(const uint*)(input);

        Vector!uint R0 = vec_ld(0, in_32);
        Vector!uint R1 = vec_ld(12, in_32);

        Vector!char perm = vec_lvsl(0, in_32);

        perm = vec_xor(perm, vec_splat_u8(3));

        R0 = vec_perm(R0, R1, perm);

        return SIMD_Altivec(R0);
    }

    static SIMD_Altivec load_bigEndian(in void* input)
    {
        const uint* in_32 = cast(const uint*)(input);

        Vector!uint R0 = vec_ld(0, in_32);
        Vector!uint R1 = vec_ld(12, in_32);

        Vector!char perm = vec_lvsl(0, in_32);

        R0 = vec_perm(R0, R1, perm);

        return SIMD_Altivec(R0);
    }

    void store_littleEndian(ubyte* output) const
    {
        Vector!char perm = vec_lvsl(0, null);

        perm = vec_xor(perm, vec_splat_u8(3));

        union {
            Vector!uint V;
            uint[4] R;
        } vec;

        vec.V = vec_perm(m_reg, m_reg, perm);

        store_bigEndian(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
    }

    void store_bigEndian(ubyte* output) const
    {
        union {
            Vector!uint V;
            uint R[4];
        } vec;

        vec.V = m_reg;

        store_bigEndian(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
    }

    void rotate_left(size_t rot)
    {
        Vector!uint rot_vec = Vector!uint([rot, rot, rot, rot]);

        m_reg = vec_rl(m_reg, rot_vec);
    }

    void rotate_right(size_t rot)
    {
        rotate_left(32 - rot);
    }

    void opOpAssign(string op)(in SIMD_Altivec other)
        if (op == "+=")
    {
        m_reg = vec_add(m_reg, other.m_reg);
    }

    SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
        if (op == "+")
    {
        return vec_add(m_reg, other.m_reg);
    }

    void opOpAssign(string op)(in SIMD_Altivec other)
        if (op == "-=")
    {
        m_reg = vec_sub(m_reg, other.m_reg);
    }

    SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
        if (op == "-")
    {
        return vec_sub(m_reg, other.m_reg);
    }

    void opOpAssign(string op)(in SIMD_Altivec other)
        if (op == "^=")
    {
        m_reg = vec_xor(m_reg, other.m_reg);
    }

    SIMD_Altivec opBinary(string op)(in SIMD_Altivec other) const
        if (op == "^")
    {
        return vec_xor(m_reg, other.m_reg);
    }

    void opOpAssign(string op)(in SIMD_Altivec other)
        if (op == "|=")
    {
        m_reg = vec_or(m_reg, other.m_reg);
    }

    SIMD_Altivec opBinary(string op)(in SIMD_Altivec other)
        if (op == "&")
    {
        return vec_and(m_reg, other.m_reg);
    }

    void opOpAssign(string op)(in SIMD_Altivec other)
        if (op == "&=")
    {
        m_reg = vec_and(m_reg, other.m_reg);
    }

    SIMD_Altivec opBinary(string op)(size_t shift) const
        if (op == "<<")
    {
        Vector!uint shift_vec =
            Vector!uint([shift, shift, shift, shift]);

        return vec_sl(m_reg, shift_vec);
    }

    SIMD_Altivec opBinary(string op)(size_t shift) const
        if (op == ">>")
    {
        Vector!uint shift_vec =
            Vector!uint([shift, shift, shift, shift]);

        return vec_sr(m_reg, shift_vec);
    }

    SIMD_Altivec opUnary(string op)() const
        if (op == "~")
    {
        return vec_nor(m_reg, m_reg);
    }

    SIMD_Altivec andc(in SIMD_Altivec other)
    {
        // AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
        return vec_andc(other.m_reg, m_reg);
    }

    SIMD_Altivec bswap() const
    {
        Vector!char perm = vec_lvsl(0, null);

        perm = vec_xor(perm, vec_splat_u8(3));

        return SIMD_Altivec(vec_perm(m_reg, m_reg, perm));
    }

    static void transpose(ref SIMD_Altivec B0, refSIMD_Altivec B1,
                                 ref SIMD_Altivec B2, ref SIMD_Altivec B3)
    {
        Vector!uint T0 = vec_mergeh(B0.m_reg, B2.m_reg);
        Vector!uint T1 = vec_mergel(B0.m_reg, B2.m_reg);
        Vector!uint T2 = vec_mergeh(B1.m_reg, B3.m_reg);
        Vector!uint T3 = vec_mergel(B1.m_reg, B3.m_reg);

        B0.m_reg = vec_mergeh(T0, T2);
        B1.m_reg = vec_mergel(T0, T2);
        B2.m_reg = vec_mergeh(T1, T3);
        B3.m_reg = vec_mergel(T1, T3);
    }

private:
    this(Vector!uint input) { m_reg = input; }

    Vector!uint m_reg;
}
