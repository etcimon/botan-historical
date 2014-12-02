/*
* HMAC_DRBG (SP800-90A)
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.rng.hmac_drbg;

import botan.constants;
static if (BOTAN_HAS_HMAC_DRBG):

import botan.rng.rng;
import botan.mac.mac;
import botan.utils.types;
import std.algorithm;

/**
* HMAC_DRBG (SP800-90A)
*/
final class HMAC_DRBG : RandomNumberGenerator
{
public:
    void randomize(ubyte* output, size_t length)
    {
        if (!is_seeded() || m_reseed_counter > BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED)
            reseed(m_mac.output_length * 8);
        
        if (!is_seeded())
            throw new PRNG_Unseeded(name);
        
        while (length)
        {
            const size_t to_copy = std.algorithm.min(length, m_V.length);
            m_V = m_mac.process(m_V);
            copy_mem(output.ptr, m_V.ptr, to_copy);
            
            length -= to_copy;
            output += to_copy;
        }
        
        m_reseed_counter += length;
        
        update(null, 0); // additional_data is always empty
    }

    bool is_seeded() const
    {
        return m_reseed_counter > 0;
    }

    void clear()
    {
        zeroise(m_V);
        
        m_mac.clear();
        
        if (m_prng)
            m_prng.clear();
    }

    @property string name() const
    {
        return "HMAC_DRBG(" ~ m_mac.name ~ ")";
    }

    void reseed(size_t poll_bits)
    {
        if (m_prng)
        {
            m_prng.reseed(poll_bits);
            
            if (m_prng.is_seeded())
            {
                Secure_Vector!ubyte input = m_prng.random_vec(m_mac.output_length);
                update(input.ptr, input.length);
                m_reseed_counter = 1;
            }
        }
    }

    void dd_entropy(in ubyte* input, size_t length)
    {
        update(input, length);
        m_reseed_counter = 1;
    }

    /**
    * @param mac the underlying mac function (eg HMAC(SHA-512))
    * @param underlying_rng RNG used generating inputs (eg HMAC_RNG)
    */
    this(MessageAuthenticationCode mac,
         RandomNumberGenerator prng)
    { 
        m_mac = mac;
        m_prng = prng;
        m_V = Secure_Vector!ubyte(m_mac.output_length, 0x01);
        m_reseed_counter = 0;
        m_mac.set_key(Secure_Vector!ubyte(m_mac.output_length, 0x00));
    }

private:
    /*
    * Reset V and the mac key with new values
    */
    void update(in ubyte* input, size_t input_len)
    {
        m_mac.update(m_V);
        m_mac.update(0x00);
        m_mac.update(input, input_len);
        m_mac.set_key(m_mac.finished());
        
        m_V = m_mac.process(m_V);
        
        if (input_len)
        {
            m_mac.update(m_V);
            m_mac.update(0x01);
            m_mac.update(input, input_len);
            m_mac.set_key(m_mac.finished());
            
            m_V = m_mac.process(m_V);
        }
    }

    Unique!MessageAuthenticationCode m_mac;
    Unique!RandomNumberGenerator m_prng;

    Secure_Vector!ubyte m_V;
    size_t m_reseed_counter;
}