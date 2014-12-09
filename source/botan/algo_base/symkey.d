/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.algo_base.symkey;

import botan.utils.xor_buf;
import botan.rng.rng;
import botan.filters.pipe;
import botan.codec.hex;
import std.algorithm;
import botan.utils.memory.zeroize;
import botan.utils.types;
// import string;

/**
* Octet String
*/
struct OctetString
{
public:
    /**
    * @return size of this octet string in bytes
    */
    @property size_t length() const { return m_bits.length; }
    
    /**
    * @return this object as a SecureVector!ubyte
    */
    SecureVector!ubyte bitsOf() const { return m_bits; }
    
    /**
    * @return start of this string
    */
    @property ubyte* ptr() const { return m_bits.ptr; }
    
    /**
    * @return end of this string
    */
    ubyte* end() const{ return begin() + m_bits.length; }
    
    /**
    * @return this encoded as hex
    */
    string toString() const
    {
        return hexEncode(m_bits.ptr, m_bits.length);
    }
        
    /**
    * XOR the contents of another octet string into this one
    * @param other = octet string
    * @return reference to this
    */
    void opOpAssign(string op)(in OctetString k)
        if (op == "^=")
    {
        if (k.ptr is this.ptr) { zeroise(m_bits); return; }
        xorBuf(m_bits.ptr, k.ptr, min(length(), k.length));
        return;
    }
    
    /**
        * Force to have odd parity
        */
    void setOddParity()
    {
        __gshared immutable ubyte[256] ODD_PARITY = [
                0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07, 0x08, 0x08, 0x0B, 0x0B,
                0x0D, 0x0D, 0x0E, 0x0E, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
                0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F, 0x20, 0x20, 0x23, 0x23,
                0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
                0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3B, 0x3B,
                0x3D, 0x3D, 0x3E, 0x3E, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
                0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x51, 0x51, 0x52, 0x52,
                0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
                0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6B, 0x6B,
                0x6D, 0x6D, 0x6E, 0x6E, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
                0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F, 0x80, 0x80, 0x83, 0x83,
                0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
                0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9B, 0x9B,
                0x9D, 0x9D, 0x9E, 0x9E, 0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
                0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE, 0xB0, 0xB0, 0xB3, 0xB3,
                0xB5, 0xB5, 0xB6, 0xB6, 0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
                0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7, 0xC8, 0xC8, 0xCB, 0xCB,
                0xCD, 0xCD, 0xCE, 0xCE, 0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
                0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF, 0xE0, 0xE0, 0xE3, 0xE3,
                0xE5, 0xE5, 0xE6, 0xE6, 0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
                0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7, 0xF8, 0xF8, 0xFB, 0xFB,
                0xFD, 0xFD, 0xFE, 0xFE ];
        
        foreach (j; 0 .. m_bits.length)
            m_bits[j] = ODD_PARITY[m_bits[j]];
    }
    
    /**
    * Create a new OctetString
    * @param str = is a hex encoded string
    */
    this(in string hex_string)
    {
        m_bits.resize(1 + hex_string.length / 2);
        m_bits.resize(hexDecode(m_bits.ptr, hex_string));
    }

    /**
    * Create a new random OctetString
    * @param rng = is a random number generator
    * @param len = is the desired length in bytes
    */
    this(RandomNumberGenerator rng, size_t length)
    {
        m_bits = rng.randomVec(length);
    }
    
    /**
    * Create a new OctetString
    * @param input = is an array
    * @param len = is the length of in in bytes
    */
    this(in ubyte* input, size_t len)
    {
        m_bits.replace(input[0 .. len]);
    }
    
    /**
    * Create a new OctetString
    * @param input = a bytestring
    */
    this(in SecureVector!ubyte input) { bits = input; }
    
    /**
    * Create a new OctetString
    * @param input = a bytestring
    */
    this(in Vector!ubyte input) {  bits = SecureVector!ubyte(input.ptr[0 .. input.length]); }


    /**
    * Compare two strings
    * @param x = an octet string
    * @param y = an octet string
    * @return if x is equal to y
    */
    bool opEquals(in OctetString other)
    {
        return (bitsOf() == other.bitsOf());
    }

    /**
    * Compare two strings
    * @param x = an octet string
    * @param y = an octet string
    * @return if x is not equal to y
    */
    bool opCmp(in OctetString other)
    {
        return !(this == other);
    }

    /**
    * Concatenate two strings
    * @param x = an octet string
    * @param y = an octet string
    * @return x concatenated with y
    */
    OctetString opBinary(string op)(in OctetString other)
        if (op == "~") 
    {
        SecureVector!ubyte output;
        output ~= bitsOf();
        output ~= other.bitsOf();
        return OctetString(output);
    }
    
    /**
    * XOR two strings
    * @param x = an octet string
    * @param y = an octet string
    * @return x XORed with y
    */
    OctetString opBinary(string op)(in OctetString other)
        if (op == "^") 
    {
        SecureVector!ubyte ret = SecureVector!ubyte(max(length(), other.length));
        
        copyMem(ret.ptr, k1.ptr, k1.length);
        xorBuf(ret.ptr, k2.ptr, k2.length);
        return OctetString(ret);
    }

private:
    SecureVector!ubyte m_bits;
}

/**
* Alternate name for octet string showing intent to use as a key
*/
alias SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
alias InitializationVector = OctetString;