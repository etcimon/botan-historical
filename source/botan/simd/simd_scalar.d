/*
* Scalar emulation of SIMD
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.simd.simd_scalar;

static if (BOTAN_HAS_SIMD_SCALAR):
import botan.utils.loadstor;
import botan.utils.bswap;

/**
* Fake SIMD, using plain scalar operations
* Often still faster than iterative on superscalar machines
*/
struct SIMDScalar(T, size_t N)
{
public:
    static bool enabled() { return true; }

    static size_t size() { return N; }

    this() { /* uninitialized */ }

    this(in T[N] B)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = B[i];
    }

    this(T B)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = B;
    }

    static SIMD_Scalar!(T, N) loadLittleEndian(in void* input)
    {
        SIMD_Scalar!(T, N) output;
        const ubyte* in_b = cast(const ubyte*)(input);

        for (size_t i = 0; i != size(); ++i)
            output.m_v[i] = loadLittleEndian!T(in_b, i);

        return output;
    }

    static SIMD_Scalar!(T, N) loadBigEndian(in void* input)
    {
        SIMD_Scalar!(T, N) output;
        const ubyte* in_b = cast(const ubyte*)(input);

        for (size_t i = 0; i != size(); ++i)
            output.m_v[i] = loadBigEndian!T(in_b, i);

        return output;
    }

    void storeLittleEndian(ubyte* output) const
    {
        for (size_t i = 0; i != size(); ++i)
            storeLittleEndian(m_v[i], output + i*T.sizeof);
    }

    void storeBigEndian(ubyte* output) const
    {
        for (size_t i = 0; i != size(); ++i)
            storeBigEndian(m_v[i], output + i*T.sizeof);
    }

    void rotateLeft(size_t rot)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = rotateLeft(m_v[i], rot);
    }

    void rotateRight(size_t rot)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = rotateRight(m_v[i], rot);
    }

    void opOpAssign(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "+=")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] += other.m_v[i];
    }

    void opOpAssign(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "-=")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] -= other.m_v[i];
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(in SIMD_Scalar!(T, N) other) const
        if (op == "+")
    {
        this += other;
        return this;
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(in SIMD_Scalar!(T, N) other) const
        if (op == "-")
    {
        this -= other;
        return this;
    }

    void opOpAssign(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "^=")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] ^= other.m_v[i];
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(in SIMD_Scalar!(T, N) other) const
        if (op == "^")
    {
        this ^= other;
        return this;
    }

    void opOpAssign(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "|=")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] |= other.m_v[i];
    }

    void opOpAssign(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "&=")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] &= other.m_v[i];
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(in SIMD_Scalar!(T, N) other)
        if (op == "&")
    {
        this &= other;
        return this;
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(size_t shift) const
        if (op == "<<")
    {
        SIMD_Scalar!(T, N) output = this;
        for (size_t i = 0; i != size(); ++i)
            output.m_v[i] <<= shift;
        return output;
    }

    ref SIMD_Scalar!(T, N) opBinary(string op)(size_t shift) const
        if (op == ">>")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] >>= shift;
        return this;
    }

    ref SIMD_Scalar!(T, N) opUnary(string op)() const
        if (op == "~")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = ~output.m_v[i];
        return this;
    }

    // (~reg) & other
    ref SIMD_Scalar!(T, N) andc(in SIMD_Scalar!(T, N) other)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = (~m_v[i]) & other.m_v[i];
        return this;
    }

    ref SIMD_Scalar!(T, N) bswap() const
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = reverse_bytes(m_v[i]);
        return this;
    }

    static void transpose(ref SIMD_Scalar!(T, N) B0, ref SIMD_Scalar!(T, N) B1,
                          ref SIMD_Scalar!(T, N) B2, ref SIMD_Scalar!(T, N) B3)
    {
        static assert(N == 4, "4x4 transpose");
        SIMD_Scalar!(T, N) T0 = SIMD_Scalar!(T, N)([B0.m_v[0], B1.m_v[0], B2.m_v[0], B3.m_v[0]]);
        SIMD_Scalar!(T, N) T1 = SIMD_Scalar!(T, N)([B0.m_v[1], B1.m_v[1], B2.m_v[1], B3.m_v[1]]);
        SIMD_Scalar!(T, N) T2 = SIMD_Scalar!(T, N)([B0.m_v[2], B1.m_v[2], B2.m_v[2], B3.m_v[2]]);
        SIMD_Scalar!(T, N) T3 = SIMD_Scalar!(T, N)([B0.m_v[3], B1.m_v[3], B2.m_v[3], B3.m_v[3]]);

        B0 = T0;
        B1 = T1;
        B2 = T2;
        B3 = T3;
    }

private:
    this(T)(T[] B)
    {
        foreach(i, v; B)
            m_v[i] = v;
    }

    T[N] m_v;
}