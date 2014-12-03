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
/**
* This class represents an elliptic curve over GF(p)
*/
struct CurveGFp
{
public:

    /**
    * Create an uninitialized CurveGFp
    */
    this() {}

    /**
    * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
    * @param p = prime number of the field
    * @param a = first coefficient
    * @param b = second coefficient
    */
    this(in BigInt p, in BigInt a, in BigInt b)
    {        
        m_p = p;
        m_a = a;
        m_b = b;
        m_p_words = m_p.sigWords();
        m_p_dash = montyInverse(m_p.wordAt(0));
        const BigInt r = BigInt.power_of_2(m_p_words * BOTAN_MP_WORD_BITS);

        m_r2  = (r * r) % p;
        m_a_r = (a * r) % p;
        m_b_r = (b * r) % p;
    }

    //this(in CurveGFp) = default;

    //CurveGFp operator=(in CurveGFp) = default;

    /**
    * @return curve coefficient a
    */
    BigInt getA() const { return m_a; }

    /**
    * @return curve coefficient b
    */
    BigInt getB() const { return m_b; }

    /**
    * Get prime modulus of the field of the curve
    * @return prime modulus of the field of the curve
    */
    BigInt getP() const { return m_p; }

    /**
    * @return Montgomery parameter r^2 % p
    */
    BigInt getR2() const { return m_r2; }

    /**
    * @return a * r mod p
    */
    BigInt getAR() const { return m_a_r; }

    /**
    * @return b * r mod p
    */
    BigInt getBR() const { return m_b_r; }

    /**
    * @return Montgomery parameter p-dash
    */
    word getPDash() const { return m_p_dash; }

    /**
    * @return p.sig_words()
    */
    size_t getPWords() const { return m_p_words; }

    /**
    * swaps the states of this and other, does not throw
    * @param other = curve to swap values with
    */
    void swap(CurveGFp other)
    {
        swap(m_p, other.m_p);

        swap(m_a, other.m_a);
        swap(m_b, other.m_b);

        swap(m_a_r, other.m_a_r);
        swap(m_b_r, other.m_b_r);

        swap(m_p_words, other.m_p_words);

        swap(m_r2, other.m_r2);
        swap(m_p_dash, other.m_p_dash);
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
    bool opCmp(string op)(in CurveGFp rhs)
        if (op == "!=")
    {
        return !(this == rhs);
    }
private:
    // Curve parameters
    BigInt m_p, m_a, m_b;

    size_t m_p_words; // cache of m_p.sig_words()

    // Montgomery parameters
    BigInt m_r2, m_a_r, m_b_r;
    word m_p_dash;
}

void swap(CurveGFp curve1, CurveGFp curve2)
{
    import std.algorithm : swap;
    curve1.swap(curve2);
}