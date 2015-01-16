/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*      2010-2011,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.ec_gfp.curve_gfp;
import botan.math.numbertheory.numthry;
import botan.math.mp.mp_types;
import std.algorithm : swap;
import botan.constants;
/**
* This class represents an elliptic curve over GF(p)
*/
struct CurveGFp
{
public:
    /**
    * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
    * @param p = prime number of the field
    * @param a = first coefficient
    * @param b = second coefficient
    */
    this(BigInt p, BigInt a, BigInt b)
    {        
        m_p = p;
        m_a = a;
        m_b = b;
        m_p_words = m_p.sigWords();
        m_p_dash = montyInverse(m_p.wordAt(0));
        BigInt r = BigInt.powerOf2(m_p_words * BOTAN_MP_WORD_BITS);

        m_r2  = (r * r) % p;
        m_a_r = (a * r) % p;
        m_b_r = (b * r) % p;
    }

    /**
    * @return curve coefficient a
    */
    const(BigInt) getA() const { return m_a; }

    /**
    * @return curve coefficient b
    */
    const(BigInt) getB() const { return m_b; }

    /**
    * Get prime modulus of the field of the curve
    * @return prime modulus of the field of the curve
    */
    const(BigInt) getP() const { return m_p; }

    /**
    * @return Montgomery parameter r^2 % p
    */
    const(BigInt) getR2() const { return m_r2; }

    /**
    * @return a * r mod p
    */
    const(BigInt) getAR() const { return m_a_r; }

    /**
    * @return b * r mod p
    */
    const(BigInt) getBR() const { return m_b_r; }

    /**
    * @return Montgomery parameter p-dash
    */
    word getPDash() const { return m_p_dash; }

    /**
    * @return p.sigWords()
    */
    size_t getPWords() const { return m_p_words; }

    /**
    * swaps the states of this and other, does not throw
    * @param other = curve to swap values with
    */
    void swap(CurveGFp other)
    {
        m_p.swap(other.m_p);

        m_a.swap(other.m_a);
        m_b.swap(other.m_b);

        m_a_r.swap(other.m_a_r);
        m_b_r.swap(other.m_b_r);

        .swap(m_p_words, other.m_p_words);

        m_r2.swap(other.m_r2);
        .swap(m_p_dash, other.m_p_dash);
    }

    /**
    * Equality operator
    * @param other = curve to compare with
    * @return true iff this is the same curve as other
    */
    bool opEquals(in CurveGFp other) const
    {
        return (m_p == other.m_p &&
                  m_a == other.m_a &&
                  m_b == other.m_b);
    }

    /**
    * Equality operator
    * @param lhs = a curve
    * @param rhs = a curve
    * @return true iff lhs is not the same as rhs
    */
    int opCmp(in CurveGFp rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

	@property CurveGFp dup() const {
        CurveGFp ret = CurveGFp(m_p.dup, m_a.dup, m_b.dup);
        ret.m_p_words = m_p_words;
        ret.m_r2 = m_r2.dup;
        ret.m_a_r = m_a_r.dup;
        ret.m_b_r = m_b_r.dup;
        ret.m_p_dash = m_p_dash;
        return ret;
    }

    const ~this() { }
private:
    // Curve parameters
    BigInt m_p, m_a, m_b;

    size_t m_p_words; // cache of m_p.sigWords()

    // Montgomery parameters
    BigInt m_r2, m_a_r, m_b_r;
    word m_p_dash;
}

void swap(CurveGFp curve1, CurveGFp curve2)
{
    import std.algorithm : swap;
    curve1.swap(curve2);
}