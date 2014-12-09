/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.x919_mac;

import botan.constants;
static if (BOTAN_HAS_ANSI_X919_MAC):

import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.xor_buf;
import std.algorithm;

/**
* DES/3DES-based MAC from ANSI X9.19
*/
final class ANSIX919MAC : MessageAuthenticationCode
{
public:
    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_des1.clear();
        m_des2.clear();
        zeroise(m_state);
        m_position = 0;
    }


	override @property string name() const
    {
        return "X9.19-MAC";
    }

	override @property size_t outputLength() const { return 8; }

	override MessageAuthenticationCode clone() const
    {
        return new ANSIX919MAC(m_des1.clone());
    }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(8, 16, 8);
    }

    /**
    * @param cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher) 
    {
        m_des1 = cipher;
        m_des2 = m_des1.clone();
        m_state = 8;
        m_position = 0;
        if (cipher.name != "DES")
            throw new InvalidArgument("ANSI X9.19 MAC only supports DES");
    }

private:
    /*
    * Update an ANSI X9.19 MAC Calculation
    */
    void addData(in ubyte* input, size_t length)
    {
        size_t xored = std.algorithm.min(8 - m_position, length);
        xorBuf(&m_state[m_position], input, xored);
        m_position += xored;
        
        if (m_position < 8) return;
        
        m_des1.encrypt(m_state);
        input += xored;
        length -= xored;
        while (length >= 8)
        {
            xorBuf(m_state, input, 8);
            m_des1.encrypt(m_state);
            input += 8;
            length -= 8;
        }
        
        xorBuf(m_state, input, length);
        m_position = length;
    }

    /*
    * Finalize an ANSI X9.19 MAC Calculation
    */
    void finalResult(ubyte* mac)
    {
        if (m_position)
            m_des1.encrypt(m_state);
        m_des2.decrypt(m_state.ptr, mac);
        m_des1.encrypt(mac);
        zeroise(m_state);
        m_position = 0;
    }


    /*
    * ANSI X9.19 MAC Key Schedule
    */
    void keySchedule(in ubyte* key, size_t length)
    {
        m_des1.setKey(key, 8);
        
        if (length == 16)
            key += 8;
        
        m_des2.setKey(key, 8);
    }


    Unique!BlockCipher m_des1, m_des2;
    SecureVector!ubyte m_state;
    size_t m_position;
}