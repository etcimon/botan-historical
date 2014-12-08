/*
* Modular Reducer
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.reducer;

import botan.math.numbertheory.numthry;
import botan.math.mp.mp_core;

/**
* Modular Reducer (using Barrett's technique)
*/
struct ModularReducer
{
public:
    BigInt getModulus() const { return m_modulus; }

    /*
    * Barrett Reduction
    */
    BigInt reduce(in BigInt x) const
    {
        if (m_mod_words == 0)
            throw new InvalidState("ModularReducer: Never initalized");
        
        if (x.cmp(m_modulus, false) < 0)
        {
            if (x.isNegative())
                return x + m_modulus; // make positive
            return x;
        }
        else if (x.cmp(m_modulus_2, false) < 0)
        {
            BigInt t1 = x;
            t1.setSign(BigInt.Positive);
            t1 >>= (MP_WORD_BITS * (m_mod_words - 1));
            t1 *= mu;
            
            t1 >>= (MP_WORD_BITS * (m_mod_words + 1));
            t1 *= modulus;
            
            t1.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            BigInt t2 = x;
            t2.setSign(BigInt.Positive);
            t2.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            t2 -= t1;
            
            if (t2.isNegative())
            {
                t2 += BigInt.powerOf2(MP_WORD_BITS * (m_mod_words + 1));
            }
            
            while (t2 >= m_modulus)
                t2 -= m_modulus;
            
            if (x.isPositive())
                return t2;
            else
                return (m_modulus - t2);
        }
        else
        {
            // too big, fall back to normal division
            return (x % m_modulus);
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
    { return reduce(square(x)); }

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
    this(in BigInt mod)
    {
        if (mod <= 0)
            throw new InvalidArgument("ModularReducer: modulus must be positive");
        
        m_modulus = mod;
        m_mod_words = m_modulus.sigWords();
        
        m_modulus_2 = square(m_modulus);
        
        m_mu = BigInt.powerOf2(2 * MP_WORD_BITS * m_mod_words) / m_modulus;
    }

private:
    BigInt m_modulus, m_modulus_2, m_mu;
    size_t m_mod_words;
}