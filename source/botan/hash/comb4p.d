/*
* Comb4P hash combiner
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.comb4p;

import botan.constants;
static if (BOTAN_HAS_COMB4P):

import botan.hash.hash;
import botan.utils.xor_buf;
import std.exception;

/**
* Combines two hash functions using a Feistel scheme. Described in
* "On the Security of Hash Function Combiners", Anja Lehmann
*/
class Comb4P : HashFunction
{
public:
    /**
    * @param h1 the first hash
    * @param h2 the second hash
    */
    this(HashFunction h1, HashFunction h2)
    {
        m_hash1 = h1;
        m_hash2 = h2;
        if (m_hash1.name == m_hash2.name)
            throw new Invalid_Argument("Comb4P: Must use two distinct hashes");
        
        if (m_hash1.output_length != m_hash2.output_length)
            throw new Invalid_Argument("Comb4P: Incompatible hashes " ~
                                       m_hash1.name ~ " and " ~
                                       m_hash2.name);
        
        clear();
    }


    @property size_t hash_block_size() const
    {
        if (m_hash1.hash_block_size == m_hash2.hash_block_size)
            return m_hash1.hash_block_size;
        
        /*
    * Return LCM of the block sizes? This would probably be OK for
    * HMAC, which is the main thing relying on knowing the block size.
    */
        return 0;
    }

    @property size_t output_length() const
    {
        return m_hash1.output_length + m_hash2.output_length;
    }

    HashFunction clone() const
    {
        return new Comb4P(m_hash1.clone(), m_hash2.clone());
    }

    @property string name() const
    {
        return "Comb4P(" ~ m_hash1.name ~ "," ~ m_hash2.name ~ ")";
    }

    void clear()
    {
        m_hash1.clear();
        m_hash2.clear();
        
        // Prep for processing next message, if any
        m_hash1.update(0);
        m_hash2.update(0);
    }
private:
    void add_data(in ubyte* input, size_t length)
    {
        m_hash1.update(input, length);
        m_hash2.update(input, length);
    }

    void final_result(ubyte* output)
    {
        Secure_Vector!ubyte h1 = m_hash1.finished();
        Secure_Vector!ubyte h2 = m_hash2.finished();
        
        // First round
        xor_buf(h1.ptr, h2.ptr, std.algorithm.min(h1.length, h2.length));
        
        // Second round
        comb4p_round(h2, h1, 1, *m_hash1, *m_hash2);
        
        // Third round
        comb4p_round(h1, h2, 2, *m_hash1, *m_hash2);
        
        copy_mem(output            , h1.ptr, h1.length);
        copy_mem(output + h1.length, h2.ptr, h2.length);
        
        // Prep for processing next message, if any
        m_hash1.update(0);
        m_hash2.update(0);
    }

    Unique!HashFunction m_hash1, m_hash2;
}

private:
    
void comb4p_round(Secure_Vector!ubyte output,
                  in Secure_Vector!ubyte input,
                  ubyte round_no,
                  HashFunction h1,
                  HashFunction h2)
{
    h1.update(round_no);
    h2.update(round_no);
    
    h1.update(input.ptr, input.length);
    h2.update(input.ptr, input.length);
    
    Secure_Vector!ubyte h_buf = h1.finished();
    xor_buf(output.ptr, h_buf.ptr, std.algorithm.min(output.length, h_buf.length));
    
    h_buf = h2.finished();
    xor_buf(output.ptr, h_buf.ptr, std.algorithm.min(output.length, h_buf.length));
}