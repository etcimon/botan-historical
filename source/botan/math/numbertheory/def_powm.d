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
final class Fixed_Window_Exponentiator : Modular_Exponentiator
{
public:
    /*
    * Set the exponent
    */
    void set_exponent(in BigInt e)
    {
        m_exp = e;
    }

    /*
    * Set the base
    */
    void set_base(in BigInt base)
    {
        m_window_bits = Power_Mod.window_bits(m_exp.bits(), base.bits(), m_hints);
        
        m_g.resize((1 << window_bits));
        m_g[0] = 1;
        m_g[1] = base;
        
        for (size_t i = 2; i != m_g.length; ++i)
            m_g[i] = m_reducer.multiply(m_g[i-1], m_g[0]);
    }

    /*
    * Compute the result
    */
    BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;
        
        BigInt x = 1;
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            foreach (size_t j; 0 .. m_window_bits)
                x = reducer.square(x);
            
            const uint nibble = exp.get_substring(m_window_bits*(i-1), m_window_bits);
            
            x = reducer.multiply(x, m_g[nibble]);
        }
        return x;
    }

    Modular_Exponentiator copy() const
    { return new Fixed_Window_Exponentiator(this); }

    this(in BigInt n, Power_Mod.Usage_Hints _hints)
    {
        m_reducer = Modular_Reducer(n);
        m_hints = _hints;
        m_window_bits = 0;
    }

private:
    Modular_Reducer m_reducer;
    BigInt m_exp;
    size_t m_window_bits;
    Vector!BigInt m_g;
    Power_Mod.Usage_Hints m_hints;
}

/**
* Montgomery Exponentiator
*/
class Montgomery_Exponentiator : Modular_Exponentiator
{
public:
    /*
    * Set the exponent
    */
    void set_exponent(in BigInt exp)
    {
        m_exp = exp;
        m_exp_bits = exp.bits();
    }

    /*
    * Set the base
    */
    void set_base(in BigInt base)
    {
        m_window_bits = Power_Mod.window_bits(m_exp.bits(), base.bits(), m_hints);
        
        m_g.resize((1 << m_window_bits));
        
        BigInt z = BigInt(BigInt.Positive, 2 * (m_mod_words + 1));
        Secure_Vector!word workspace(z.length);
        
        m_g[0] = 1;
        
        bigint_monty_mul(z.mutable_data(), z.length, m_g[0].data(), m_g[0].length, m_g[0].sig_words(), m_R2_mod.data(), 
                         m_R2_mod.length, m_R2_mod.sig_words(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[0] = z;
        
        m_g[1] = (base >= m_modulus) ? (base % m_modulus) : base;
        
        bigint_monty_mul(z.mutable_data(), z.length, m_g[1].data(), m_g[1].length, m_g[1].sig_words(), m_R2_mod.data(), 
                         m_R2_mod.length, m_R2_mod.sig_words(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[1] = z;
        
        const BigInt x = m_g[1];
        const size_t x_sig = x.sig_words();
        
        for (size_t i = 2; i != m_g.length; ++i)
        {
            const BigInt y = m_g[i-1];
            const size_t y_sig = y.sig_words();
            
            bigint_monty_mul(z.mutable_data(), z.length,
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
    BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;
        
        BigInt x = m_R_mod;
        
        const size_t z_size = 2*(m_mod_words + 1);
        
        BigInt z = BigInt(BigInt.Positive, z_size);
        Secure_Vector!word workspace(z_size);
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            for (size_t k = 0; k != m_window_bits; ++k)
            {
                bigint_monty_sqr(z.mutable_data(), z_size, x.data(), x.length, x.sig_words(),
                                 m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
                
                x = z;
            }
            
            const uint nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);
            
            const BigInt y = m_g[nibble];

            bigint_monty_mul(z.mutable_data(), z_size, x.data(), x.length, x.sig_words(), y.data(), y.length, y.sig_words(),
                             m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);

            x = z;
        }
        
        x.grow_to(2*m_mod_words + 1);
        
        bigint_monty_redc(x.mutable_data(), m_modulus.data(), m_mod_words, m_mod_prime, workspace.ptr);
        
        return x;
    }

    Modular_Exponentiator copy() const
    { return new Montgomery_Exponentiator(this); }

    /*
    * Montgomery_Exponentiator Constructor
    */
    this(in BigInt mod,
         Power_Mod.Usage_Hints hints)
    {
        m_modulus = mod;
        m_mod_words = m_modulus.sig_words();
        m_window_bits = 1;
        m_hints = hints;
        // Montgomery reduction only works for positive odd moduli
        if (!m_modulus.is_positive() || m_modulus.is_even())
            throw new Invalid_Argument("Montgomery_Exponentiator: invalid modulus");
        
        m_mod_prime = monty_inverse(mod.word_at(0));
        
        const BigInt r = BigInt.power_of_2(m_mod_words * BOTAN_MP_WORD_BITS);
        m_R_mod = r % m_modulus;
        m_R2_mod = (m_R_mod * m_R_mod) % m_modulus;
    }
private:
    BigInt m_exp, m_modulus, m_R_mod, m_R2_mod;
    word m_mod_prime;
    size_t m_mod_words, m_exp_bits, m_window_bits;
    Power_Mod.Usage_Hints m_hints;
    Vector!( BigInt ) m_g;
}

