/*
* Modular Reducer
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.reducer;

import botan.constants;
import botan.math.numbertheory.numthry;
import botan.math.mp.mp_core;

/**
* Modular Reducer (using Barrett's technique)
*/
struct ModularReducer
{
public:
    const(BigInt) getModulus() const { return m_modulus; }

    /*
    * Barrett Reduction
    */
    BigInt reduce(BigInt x) const
    {
        BigInt modulus = m_modulus.dup;
        if (m_mod_words == 0)
            throw new InvalidState("ModularReducer: Never initalized");
        
        if (x.cmp(modulus, false) < 0)
        {
            if (x.isNegative())
                return x + modulus; // make positive
            return x;
        }
        else if (x.cmp(m_modulus_2, false) < 0)
        {
            BigInt t1 = x.dup;
            t1.setSign(BigInt.Positive);
            t1 >>= (MP_WORD_BITS * (m_mod_words - 1));
            t1 *= m_mu;
            
            t1 >>= (MP_WORD_BITS * (m_mod_words + 1));
            t1 *= modulus;
            
            t1.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            BigInt t2 = x.dup;
            t2.setSign(BigInt.Positive);
            t2.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            t2 -= t1;
            
            if (t2.isNegative())
            {
                t2 += BigInt.powerOf2(MP_WORD_BITS * (m_mod_words + 1));
            }
            
            while (t2 >= modulus)
                t2 -= modulus;
            
            if (x.isPositive())
                return t2;
            else
                return (modulus - t2);
        }
        else
        {
            // too big, fall back to normal division
            return (x % modulus);
        }
    }

    /**
    * Multiply mod p
    * @param x
    * @param y
    * @return (x * y) % p
    */
    BigInt multiply(in BigInt x, in BigInt y) const
    { return reduce(x * y); }

    /**
    * Square mod p
    * @param x
    * @return (x * x) % p
    */
    BigInt square(in BigInt x) const
    { return reduce(x.square()); }

    /**
    * Cube mod p
    * @param x
    * @return (x * x * x) % p
    */
    BigInt cube(in BigInt x) const
    { return multiply(x, this.square(x)); }

    bool initialized() const { return (m_mod_words != 0); }
    /*
    * ModularReducer Constructor
    */
    this(BigInt mod)
    {
        if (mod <= 0)
            throw new InvalidArgument("ModularReducer: modulus must be positive");
        logTrace("Set mod");
        m_modulus = mod;
        logTrace("Get sigWords");
        m_mod_words = m_modulus.sigWords();
        logTrace("square");
        
        m_modulus_2 = square(m_modulus);
        logTrace("power2");
        
        m_mu = BigInt.powerOf2(2 * MP_WORD_BITS * m_mod_words) / m_modulus;
    }

    @property ModularReducer dup() const {
        ModularReducer ret = ModularReducer.init;
        ret.m_modulus = m_modulus.dup;
        ret.m_modulus_2 = m_modulus_2.dup;
        ret.m_mu = m_mu.dup;
        ret.m_mod_words = m_mod_words;
        return ret;
    }

private:
    BigInt m_modulus, m_modulus_2, m_mu;
    size_t m_mod_words;
}