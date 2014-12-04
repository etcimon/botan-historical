/*
* CMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cmac.cmac;

import botan.constants;

static if (BOTAN_HAS_CMAC):

import botan.utils.types;
import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.xorBuf;
/**
* CMAC, also known as OMAC1
*/
final class CMAC : MessageAuthenticationCode
{
public:
    /*
    * Return the name of this type
    */
    @property string name() const
    {
        return "CMAC(" ~ m_cipher.name ~ ")";
    }

    @property size_t outputLength() const { return m_cipher.blockSize(); }
    /*
    * Return a clone of this object
    */
    MessageAuthenticationCode clone() const
    {
        return new CMAC(m_cipher.clone());
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_cipher.clear();
        zeroise(m_state);
        zeroise(m_buffer);
        zeroise(m_B);
        zeroise(m_P);
        m_position = 0;
    }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    /**
    * CMAC's polynomial doubling operation
    * @param input = the input
    * @param polynomial = the ubyte value of the polynomial
    */
    SecureVector!ubyte polyDouble(in SecureVector!ubyte input)
    {
        const bool top_carry = (input[0] & 0x80);
        
        SecureVector!ubyte output = input;
        
        ubyte carry = 0;
        for (size_t i = output.length; i != 0; --i)
        {
            ubyte temp = output[i-1];
            output[i-1] = (temp << 1) | carry;
            carry = (temp >> 7);
        }
        
        if (top_carry)
        {
            switch(input.length)
            {
                case 8:
                    output[$-1] ^= 0x1B;
                    break;
                case 16:
                    output[$-1] ^= 0x87;
                    break;
                case 32:
                    output[$-2] ^= 0x4;
                    output[$-1] ^= 0x25;
                    break;
                case 64:
                    output[$-2] ^= 0x1;
                    output[$-1] ^= 0x25;
                    break;
            }
        }
        
        return output;
    }

    /**
    * @param cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher)
    {
        m_cipher = cipher;
        if (m_cipher.blockSize() !=  8 && m_cipher.blockSize() != 16 &&
            m_cipher.blockSize() != 32 && m_cipher.blockSize() != 64)
        {
            throw new InvalidArgument("CMAC cannot use the " ~
                                       to!string(m_cipher.blockSize() * 8) ~
                                       " bit cipher " ~ m_cipher.name);
        }
        
        m_state.resize(output_length());
        m_buffer.resize(output_length());
        m_B.resize(output_length());
        m_P.resize(output_length());
        m_position = 0;
    }

private:
    /*
    * Update an CMAC Calculation
    */
    void addData(in ubyte* input, size_t length)
    {
        buffer_insert(m_buffer, m_position, input, length);
        if (m_position + length > output_length())
        {
            xorBuf(m_state, m_buffer, output_length());
            m_cipher.encrypt(m_state);
            input += (output_length() - m_position);
            length -= (output_length() - m_position);
            while (length > output_length())
            {
                xorBuf(m_state, input, output_length());
                m_cipher.encrypt(m_state);
                input += output_length();
                length -= output_length();
            }
            copyMem(m_buffer.ptr, input, length);
            m_position = 0;
        }
        m_position += length;
    }

    /*
    * Finalize an CMAC Calculation
    */
    void finalResult(ubyte* mac)
    {
        xorBuf(m_state, m_buffer, m_position);
        
        if (m_position == output_length())
        {
            xorBuf(m_state, m_B, output_length());
        }
        else
        {
            m_state[m_position] ^= 0x80;
            xorBuf(m_state, m_P, output_length());
        }
        
        m_cipher.encrypt(m_state);
        
        for (size_t i = 0; i != output_length(); ++i)
            mac[i] = m_state[i];
        
        zeroise(m_state);
        zeroise(m_buffer);
        m_position = 0;
    }

    /*
    * CMAC Key Schedule
    */
    void keySchedule(in ubyte* key, size_t length)
    {
        clear();
        m_cipher.setKey(key, length);
        m_cipher.encrypt(m_B);
        m_B = poly_double(m_B);
        m_P = poly_double(m_B);
    }


    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_buffer, m_state, m_B, m_P;
    size_t m_position;
}