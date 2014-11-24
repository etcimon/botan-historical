/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.tea;

import botan.constants;
static if (BOTAN_HAS_TEA):

import botan.block.block_cipher;
import botan.utils.loadstor;
/**
* TEA
*/
final class TEA : Block_Cipher_Fixed_Params!(8, 16)
{
public:
    /*
    * TEA Encryption
    */
    void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = load_be!uint(input, 0);
            uint R = load_be!uint(input, 1);
            
            uint S = 0;
            foreach (size_t j; 0 .. 32)
            {
                S += 0x9E3779B9;
                L += ((R << 4) + m_K[0]) ^ (R + S) ^ ((R >> 5) + m_K[1]);
                R += ((L << 4) + m_K[2]) ^ (L + S) ^ ((L >> 5) + m_K[3]);
            }
            
            store_be(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    /*
    * TEA Decryption
    */
    void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = load_be!uint(input, 0);
            uint R = load_be!uint(input, 1);
            
            uint S = 0xC6EF3720;
            foreach (size_t j; 0 .. 32)
            {
                R -= ((L << 4) + m_K[2]) ^ (L + S) ^ ((L >> 5) + m_K[3]);
                L -= ((R << 4) + m_K[0]) ^ (R + S) ^ ((R >> 5) + m_K[1]);
                S -= 0x9E3779B9;
            }
            
            store_be(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    void clear()
    {
        zap(m_K);
    }

    override @property string name() const { return "TEA"; }
    BlockCipher clone() const { return new TEA; }
private:
    /*
    * TEA Key Schedule
    */
    void key_schedule(in ubyte* key, size_t)
    {
        m_K.resize(4);
        foreach (size_t i; 0 .. 4)
            m_K[i] = load_be!uint(key, i);
    }
    Secure_Vector!uint m_K;
}