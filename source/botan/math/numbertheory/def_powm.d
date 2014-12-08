/*
* Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.def_powm;

import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.reducer;
import botan.math.bigint.bigint;
import botan.utils.types;

/**
* Fixed Window Exponentiator
*/
final class FixedWindowExponentiator : ModularExponentiator
{
public:
    /*
    * Set the exponent
    */
    override void setExponent(in BigInt e)
    {
        m_exp = e;
    }

    /*
    * Set the base
    */
	override void setBase(in BigInt base)
    {
        m_window_bits = PowerMod.windowBits(m_exp.bits(), base.bits(), m_hints);
        
        m_g.resize((1 << window_bits));
        m_g[0] = 1;
        m_g[1] = base;
        
        for (size_t i = 2; i != m_g.length; ++i)
            m_g[i] = m_reducer.multiply(m_g[i-1], m_g[0]);
    }

    /*
    * Compute the result
    */
	override BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;
        
        BigInt x = 1;
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            foreach (size_t j; 0 .. m_window_bits)
                x = reducer.square(x);
            
            const uint nibble = exp.getSubstring(m_window_bits*(i-1), m_window_bits);
            
            x = reducer.multiply(x, m_g[nibble]);
        }
        return x;
    }

	override ModularExponentiator copy() const
    { return new FixedWindowExponentiator(this); }

    this(in BigInt n, PowerMod.UsageHints _hints)
    {
        m_reducer = ModularReducer(n);
        m_hints = _hints;
        m_window_bits = 0;
    }

private:
    ModularReducer m_reducer;
    BigInt m_exp;
    size_t m_window_bits;
    Vector!BigInt m_g;
    PowerMod.UsageHints m_hints;
}

/**
* Montgomery Exponentiator
*/
class MontgomeryExponentiator : ModularExponentiator
{
public:
    /*
    * Set the exponent
    */
	override void setExponent(in BigInt exp)
    {
        m_exp = exp;
        m_exp_bits = exp.bits();
    }

    /*
    * Set the base
    */
	override void setBase(in BigInt base)
    {
        m_window_bits = PowerMod.windowBits(m_exp.bits(), base.bits(), m_hints);
        
        m_g.resize((1 << m_window_bits));
        
        BigInt z = BigInt(BigInt.Positive, 2 * (m_mod_words + 1));
        SecureVector!word workspace(z.length);
        
        m_g[0] = 1;
        
        bigint_monty_mul(z.mutableData(), z.length, m_g[0].data(), m_g[0].length, m_g[0].sigWords(), m_R2_mod.data(), 
                         m_R2_mod.length, m_R2_mod.sigWords(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[0] = z;
        
        m_g[1] = (base >= m_modulus) ? (base % m_modulus) : base;
        
        bigint_monty_mul(z.mutableData(), z.length, m_g[1].data(), m_g[1].length, m_g[1].sigWords(), m_R2_mod.data(), 
                         m_R2_mod.length, m_R2_mod.sigWords(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[1] = z;
        
        const BigInt x = m_g[1];
        const size_t x_sig = x.sigWords();
        
        for (size_t i = 2; i != m_g.length; ++i)
        {
            const BigInt y = m_g[i-1];
            const size_t y_sig = y.sigWords();
            
            bigint_monty_mul(z.mutableData(), z.length,
                             x.data(), x.length, x_sig,
                             y.data(), y.length, y_sig,
                             m_modulus.data(), m_mod_words, m_mod_prime,
                             workspace.ptr);
            
            m_g[i] = z;
        }
    }

    /*
    * Compute the result
    */
	override BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;
        
        BigInt x = m_R_mod;
        
        const size_t z_size = 2*(m_mod_words + 1);
        
        BigInt z = BigInt(BigInt.Positive, z_size);
        SecureVector!word workspace(z_size);
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            for (size_t k = 0; k != m_window_bits; ++k)
            {
                bigint_monty_sqr(z.mutableData(), z_size, x.data(), x.length, x.sigWords(),
                                 m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
                
                x = z;
            }
            
            const uint nibble = m_exp.getSubstring(m_window_bits*(i-1), m_window_bits);
            
            const BigInt y = m_g[nibble];

            bigint_monty_mul(z.mutableData(), z_size, x.data(), x.length, x.sigWords(), y.data(), y.length, y.sigWords(),
                             m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);

            x = z;
        }
        
        x.growTo(2*m_mod_words + 1);
        
        bigint_monty_redc(x.mutableData(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        return x;
    }

	override ModularExponentiator copy() const
    { return new MontgomeryExponentiator(this); }

    /*
    * Montgomery_Exponentiator Constructor
    */
    this(in BigInt mod,
         PowerMod.UsageHints hints)
    {
        m_modulus = mod;
        m_mod_words = m_modulus.sigWords();
        m_window_bits = 1;
        m_hints = hints;
        // Montgomery reduction only works for positive odd moduli
        if (!m_modulus.isPositive() || m_modulus.isEven())
            throw new InvalidArgument("Montgomery_Exponentiator: invalid modulus");
        
        m_mod_prime = montyInverse(mod.wordAt(0));
        
        const BigInt r = BigInt.powerOf2(m_mod_words * BOTAN_MP_WORD_BITS);
        m_R_mod = r % m_modulus;
        m_R2_mod = (m_R_mod * m_R_mod) % m_modulus;
    }
private:
    BigInt m_exp, m_modulus, m_R_mod, m_R2_mod;
    word m_mod_prime;
    size_t m_mod_words, m_exp_bits, m_window_bits;
    PowerMod.UsageHints m_hints;
    Vector!BigInt m_g;
}

