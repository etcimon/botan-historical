/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.cbc_mac;

import botan.constants;
static if (BOTAN_HAS_CBC_MAC):

import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.xorBuf;
import std.algorithm;

/**
* CBC-MAC
*/
final class CBCMAC : MessageAuthenticationCode
{
public:
    /*
    * Return the name of this type
    */
    @property string name() const
    {
        return "CBC-MAC(" ~ m_cipher.name ~ ")";
    }

    /*
    * Return a clone of this object
    */
    MessageAuthenticationCode clone() const
    {
        return new CBCMAC(m_cipher.clone());
    }

    @property size_t outputLength() const { return m_cipher.blockSize(); }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_cipher.clear();
        zeroise(m_state);
        m_position = 0;
    }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    /**
    * @param cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher)
    {
        m_cipher = cipher;
        m_state = cipher.blockSize();
    }


private:
    /*
    * Update an CBC-MAC Calculation
    */
    void addData(in ubyte* input, size_t length)
    {
        size_t xored = std.algorithm.min(output_length() - m_position, length);
        xorBuf(&m_state[m_position], input, xored);
        m_position += xored;
        
        if (m_position < output_length())
            return;
        
        m_cipher.encrypt(m_state);
        input += xored;
        length -= xored;
        while (length >= output_length())
        {
            xorBuf(m_state, input, output_length());
            m_cipher.encrypt(m_state);
            input += output_length();
            length -= output_length();
        }
        
        xorBuf(m_state, input, length);
        m_position = length;
    }    

    /*
    * Finalize an CBC-MAC Calculation
    */
    void finalResult(ubyte* mac)
    {
        if (m_position)
            m_cipher.encrypt(m_state);
        
        copyMem(mac, m_state.ptr, m_state.length);
        zeroise(m_state);
        m_position = 0;
    }

    /*
    * CBC-MAC Key Schedule
    */
    void keySchedule(in ubyte* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_state;
    size_t m_position;
}