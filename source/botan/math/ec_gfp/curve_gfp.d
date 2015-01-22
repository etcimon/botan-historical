/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*      2010-2011,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.ec_gfp.curve_gfp;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.numbertheory.numthry;
import botan.math.mp.mp_types;
import std.algorithm : swap;
import botan.constants;
/**
* This class represents an elliptic curve over GF(p)
*/
struct CurveGFp
{
	this(CurveGFp curve) {
		logTrace("curveGFp constructor");
	}

	this(BigInt p, BigInt a, BigInt b, size_t m_p_words, BigInt r2, BigInt a_r, BigInt b_r, word p_dash) {
		logTrace("curveGFp constructor 2");
	}
	
	/**
    * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
    * @param p = prime number of the field
    * @param a = first coefficient
    * @param b = second coefficient
    */
    this(BigInt p, BigInt a, BigInt b)
    {
		logTrace("CurveGFp constructor 3");
        m_p = p;
        m_a = a;
        m_b = b;
        m_p_words = m_p.sigWords();
        m_p_dash = montyInverse(m_p.wordAt(0));
        BigInt r = BigInt.powerOf2(m_p_words * BOTAN_MP_WORD_BITS);

        m_r2  = (r * r) % m_p;
        m_a_r = (m_a * r) % m_p;
        m_b_r = (m_b * r) % m_p;
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
    void swap(ref CurveGFp other)
    {
		logTrace("curveGFp swap");
        m_p.swap(other.m_p);
        m_a.swap(other.m_a);
        m_b.swap(other.m_b);
        m_a_r.swap(other.m_a_r);
        m_b_r.swap(other.m_b_r);
        m_p_words = other.m_p_words;
        m_r2.swap(other.m_r2);
        m_p_dash = other.m_p_dash;
    }

    /**
    * Equality operator
    * @param other = curve to compare with
    * @return true iff this is the same curve as other
    */
    bool opEquals(const ref CurveGFp other) const
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
    int opCmp(ref CurveGFp rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

    @property CurveGFp dup() const {
		logTrace("CurveGFp dup");
		logDebug(toArray()[]);
		return CurveGFp(m_p.dup(), m_a.dup(), m_b.dup());
    }

	@disable this(this);

	string toString() const {
		return toArray()[].idup;
	}

	Array!ubyte toArray() const {
		Array!ubyte ret;
		ret ~= "m_p: ";
		ret ~= m_p.toString();
		ret ~= "\nm_a: ";
		ret ~= m_a.toString();
		ret ~= "\nm_b: ";
		ret ~= m_b.toString();
		ret ~= "\nm_r2: ";
		ret ~= m_r2.toString();
		ret ~= "\nm_a_r: ";
		ret ~= m_a_r.toString();
		ret ~= "\nm_b_r: ";
		ret ~= m_b_r.toString();
		ret ~= "\nm_p_dash: ";
		ret ~= m_p_dash.to!string;
		ret ~= "\nm_p_words: ";
		ret ~= m_p_words.to!string;
		ret ~= "\n";
		return ret;
	}

	~this() {
	}

	// Curve parameters
	BigInt m_p, m_a, m_b;
	
	size_t m_p_words; // cache of m_p.sigWords()
	
	// Montgomery parameters
	BigInt m_r2, m_a_r, m_b_r;
	word m_p_dash;

}
