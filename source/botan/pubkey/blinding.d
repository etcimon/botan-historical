/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.blinding;

import botan.math.bigint.bigint;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;

/**
* Blinding Function Object
*/
struct Blinder
{
public:
    /*
    * Blind a number
    */
    BigInt blind(in BigInt i)
    {
        if (!m_reducer.initialized())
            return i;
        
        m_e = m_reducer.square(e);
        m_d = m_reducer.square(d);
        return m_reducer.multiply(i, m_e);
    }

    /*
    * Unblind a number
    */
    BigInt unblind(in BigInt i) const
    {
        if (!m_reducer.initialized())
            return i;
        return m_reducer.multiply(i, m_d);
    }

    bool initialized() const { return m_reducer.initialized(); }

    this() {}

    /**
    * Construct a blinder
    * @param e = the forward (blinding) mask
    * @param d = the inverse of mask (depends on algo)
    * @param n = modulus of the group operations are performed in
    */
    this(in BigInt e, in BigInt d, in BigInt n)
    {
        if (e < 1 || d < 1 || n < 1)
            throw new InvalidArgument("Blinder: Arguments too small");
        
        m_reducer = ModularReducer(n);
        m_e = e;
        m_d = d;
    }

private:
    ModularReducer m_reducer;
    BigInt m_e, m_d;
}