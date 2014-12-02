/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.pssr;

import botan.pk_pad.emsa;
import botan.m_hash.m_hash;
import botan.utils.types;
import botan.pk_pad.mgf1;
import botan.utils.bit_ops;
import botan.utils.xor_buf;



/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR : EMSA
{
public:

    /**
    * @param hash = the hash object to use
    */
    this(HashFunction hash)
    {
        m_SALT_SIZE = h.output_length;
        m_hash = hash;
    }

    /**
    * @param hash = the hash object to use
    * @param salt_size = the size of the salt to use in bytes
    */
    this(HashFunction hash, size_t salt_size)
    {
        m_SALT_SIZE = salt_size;
        m_hash = hash;
    }
private:
    /*
    * PSSR Update Operation
    */
    void update(in ubyte* input, size_t length)
    {
        m_hash.update(input, length);
    }

    /*
    * Return the raw (unencoded) data
    */
    Secure_Vector!ubyte raw_data()
    {
        return m_hash.finished();
    }

    /*
    * PSSR Encode Operation
    */
    Secure_Vector!ubyte encoding_of(in Secure_Vector!ubyte msg,
                                 size_t output_bits,
                                 RandomNumberGenerator rng)
    {
        const size_t HASH_SIZE = m_hash.output_length;
        
        if (msg.length != HASH_SIZE)
            throw new Encoding_Error("encoding_of: Bad input length");
        if (output_bits < 8*HASH_SIZE + 8*m_SALT_SIZE + 9)
            throw new Encoding_Error("encoding_of: Output length is too small");
        
        const size_t output_length = (output_bits + 7) / 8;
        
        Secure_Vector!ubyte salt = rng.random_vec(m_SALT_SIZE);
        
        foreach (size_t j; 0 .. 8)
            m_hash.update(0);
        m_hash.update(msg);
        m_hash.update(salt);
        Secure_Vector!ubyte H = m_hash.finished();
        
        Secure_Vector!ubyte EM = Secure_Vector!ubyte(output_length);
        
        EM[output_length - HASH_SIZE - m_SALT_SIZE - 2] = 0x01;
        buffer_insert(EM, output_length - 1 - HASH_SIZE - m_SALT_SIZE, salt);
        mgf1_mask(*m_hash, H.ptr, HASH_SIZE, EM.ptr, output_length - HASH_SIZE - 1);
        EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
        buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
        EM[output_length-1] = 0xBC;
        
        return EM;
    }

    /*
    * PSSR Decode/Verify Operation
    */
    bool verify(in Secure_Vector!ubyte const_coded,
                in Secure_Vector!ubyte raw, size_t key_bits)
    {
        const size_t HASH_SIZE = m_hash.output_length;
        const size_t KEY_BYTES = (key_bits + 7) / 8;
        
        if (key_bits < 8*HASH_SIZE + 9)
            return false;
        
        if (raw.length != HASH_SIZE)
            return false;
        
        if (const_coded.length > KEY_BYTES || const_coded.length <= 1)
            return false;
        
        if (const_coded[const_coded.length-1] != 0xBC)
            return false;
        
        Secure_Vector!ubyte coded = const_coded;
        if (coded.length < KEY_BYTES)
        {
            Secure_Vector!ubyte temp = Secure_Vector!ubyte(KEY_BYTES);
            buffer_insert(temp, KEY_BYTES - coded.length, coded);
            coded = temp;
        }
        
        const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
        if (TOP_BITS > 8 - high_bit(coded[0]))
            return false;
        
        ubyte* DB = coded.ptr;
        const size_t DB_size = coded.length - HASH_SIZE - 1;
        
        const ubyte* H = &coded[DB_size];
        const size_t H_size = HASH_SIZE;
        
        mgf1_mask(*m_hash, H.ptr, H_size, DB.ptr, DB_size);
        DB[0] &= 0xFF >> TOP_BITS;
        
        size_t salt_offset = 0;
        foreach (size_t j; 0 .. DB_size)
        {
            if (DB[j] == 0x01)
            { salt_offset = j + 1; break; }
            if (DB[j])
                return false;
        }
        if (salt_offset == 0)
            return false;
        
        foreach (size_t j; 0 .. 8)
            m_hash.update(0);
        m_hash.update(raw);
        m_hash.update(&DB[salt_offset], DB_size - salt_offset);
        Secure_Vector!ubyte H2 = m_hash.finished();
        
        return same_mem(H.ptr, H2.ptr, HASH_SIZE);
    }

    size_t m_SALT_SIZE;
    Unique!HashFunction m_hash;
}
