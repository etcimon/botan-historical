/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.idea;

import botan.constants;
static if (BOTAN_HAS_IDEA):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.types;

/**
* IDEA
*/
class IDEA : Block_Cipher_Fixed_Params!(8, 16)
{
public:
    /*
    * IDEA Encryption
    */
    void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        idea_op(input, output, blocks, m_EK.ptr);
    }

    /*
    * IDEA Decryption
    */
    void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        idea_op(input, output, blocks, m_DK.ptr);
    }

    void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    @property string name() const { return "IDEA"; }
    BlockCipher clone() const { return new IDEA; }
protected:
    /**
    * @return const reference to encryption subkeys
    */
    Secure_Vector!ushort get_EK() const { return m_EK; }

    /**
    * @return const reference to decryption subkeys
    */
    Secure_Vector!ushort get_DK() const { return m_DK; }

private:
    /*
    * IDEA Key Schedule
    */
    void key_schedule(in ubyte* key, size_t)
    {
        m_EK.resize(52);
        m_DK.resize(52);
        
        foreach (size_t i; 0 .. 8)
            m_EK[i] = load_bigEndian!ushort(key, i);
        
        for (size_t i = 1, j = 8, offset = 0; j != 52; i %= 8, ++i, ++j)
        {
            m_EK[i+7+offset] = cast(ushort)((m_EK[(i      % 8) + offset] << 9) |
                                              (m_EK[((i+1) % 8) + offset] >> 7));
            offset += (i == 8) ? 8 : 0;
        }
        
        m_DK[51] = mul_inv(m_EK[3]);
        m_DK[50] = -m_EK[2];
        m_DK[49] = -m_EK[1];
        m_DK[48] = mul_inv(m_EK[0]);
        
        for (size_t i = 1, j = 4, counter = 47; i != 8; ++i, j += 6)
        {
            m_DK[counter--] = m_EK[j+1];
            m_DK[counter--] = m_EK[j];
            m_DK[counter--] = mul_inv(m_EK[j+5]);
            m_DK[counter--] = -m_EK[j+3];
            m_DK[counter--] = -m_EK[j+4];
            m_DK[counter--] = mul_inv(m_EK[j+2]);
        }
        
        m_DK[5] = m_EK[47];
        m_DK[4] = m_EK[46];
        m_DK[3] = mul_inv(m_EK[51]);
        m_DK[2] = -m_EK[50];
        m_DK[1] = -m_EK[49];
        m_DK[0] = mul_inv(m_EK[48]);
    }

    Secure_Vector!ushort m_EK, m_DK;
}

package:
    
/*
* Multiplication modulo 65537
*/
ushort mul(ushort x, ushort y) pure
{
    const uint P = cast(uint)(x) * y;
    
    // P ? 0xFFFF : 0
    const ushort P_mask = !P - 1;
    
    const uint P_hi = P >> 16;
    const uint P_lo = P & 0xFFFF;
    
    const ushort r_1 = (P_lo - P_hi) + (P_lo < P_hi);
    const ushort r_2 = 1 - x - y;
    
    return (r_1 & P_mask) | (r_2 & ~P_mask);
}

/*
* Find multiplicative inverses modulo 65537
*
* 65537 is prime; thus Fermat's little theorem tells us that
* x^65537 == x modulo 65537, which means
* x^(65537-2) == x^-1 modulo 65537 since
* x^(65537-2) * x == 1 mod 65537
*
* Do the exponentiation with a basic square and multiply: all bits are
* of exponent are 1 so we always multiply
*/
ushort mul_inv(ushort x) pure
{
    ushort y = x;
    
    foreach (size_t i; 0 .. 15)
    {
        y = mul(y, y); // square
        y = mul(y, x);
    }
    
    return y;
}

/**
* IDEA is involutional, depending only on the key schedule
*/
void idea_op(ubyte* input, ubyte* output, size_t blocks) pure
{
    __gshared immutable size_t BLOCK_SIZE = 8;
    
    foreach (size_t i; 0 .. blocks)
    {
        ushort X1 = load_bigEndian!ushort(input, 0);
        ushort X2 = load_bigEndian!ushort(input, 1);
        ushort X3 = load_bigEndian!ushort(input, 2);
        ushort X4 = load_bigEndian!ushort(input, 3);
        
        foreach (size_t j; 0 .. 8)
        {
            X1 = mul(X1, K[6*j+0]);
            X2 += K[6*j+1];
            X3 += K[6*j+2];
            X4 = mul(X4, K[6*j+3]);
            
            ushort T0 = X3;
            X3 = mul(X3 ^ X1, K[6*j+4]);
            
            ushort T1 = X2;
            X2 = mul((X2 ^ X4) + X3, K[6*j+5]);
            X3 += X2;
            
            X1 ^= X2;
            X4 ^= X3;
            X2 ^= T0;
            X3 ^= T1;
        }
        
        X1  = mul(X1, K[48]);
        X2 += K[50];
        X3 += K[49];
        X4  = mul(X4, K[51]);
        
        store_bigEndian(output, X1, X3, X2, X4);
        
        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
    }
}
