/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa_raw;

import botan.pk_pad.emsa;
/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
final class EMSARaw : EMSA
{
private:
    /*
    * EMSA-Raw Encode Operation
    */
    void update(in ubyte* input, size_t length)
    {
        m_message += Pair(input, length);
    }

    /*
    * Return the raw (unencoded) data
    */
    SecureVector!ubyte rawData()
    {
        SecureVector!ubyte output;
        std.algorithm.swap(m_message, output);
        return output;
    }

    /*
    * EMSA-Raw Encode Operation
    */
    SecureVector!ubyte encodingOf(in SecureVector!ubyte msg,
                                 size_t,
                                 RandomNumberGenerator)
    {
        return msg;
    }

    /*
    * EMSA-Raw Verify Operation
    */
    bool verify(in SecureVector!ubyte coded,
                in SecureVector!ubyte raw,
                size_t)
    {
        if (coded.length == raw.length)
            return (coded == raw);
        
        if (coded.length > raw.length)
            return false;
        
        // handle zero padding differences
        const size_t leading_zeros_expected = raw.length - coded.length;
        
        bool same_modulo_leading_zeros = true;
        
        foreach (size_t i; 0 .. leading_zeros_expected)
            if (raw[i])
                same_modulo_leading_zeros = false;
        
        if (!sameMem(coded.ptr, &raw[leading_zeros_expected], coded.length))
            same_modulo_leading_zeros = false;
        
        return same_modulo_leading_zeros;
    }

    SecureVector!ubyte m_message;
}