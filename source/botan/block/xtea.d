/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.xtea;

import botan.constants;
static if (BOTAN_HAS_XTEA):

import std.range : iota;
import botan.block.block_cipher;
import botan.utils.loadstor;
/**
* XTEA
*/
class XTEA : Block_Cipher_Fixed_Params!(8, 16)
{
public:
    /*
    * XTEA Encryption
    */
    void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        while (blocks >= 4)
        {
            xtea_encrypt_4(*cast(ubyte[32]*) input, *cast(ubyte[32]*) output, *cast(uint[64]*) m_EK.ptr);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            uint L = load_bigEndian!uint(input, 0);
            uint R = load_bigEndian!uint(input, 1);
            
            foreach (size_t j; 0 .. 32)
            {
                L += (((R << 4) ^ (R >> 5)) + R) ^ m_EK[2*j];
                R += (((L << 4) ^ (L >> 5)) + L) ^ m_EK[2*j+1];
            }
            
            store_bigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    
    /*
    * XTEA Decryption
    */
    void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        while (blocks >= 4)
        {
            xtea_decrypt_4(*cast(ubyte[32]*) input, *cast(ubyte[32]*) output, *cast(uint[64]*) m_EK.ptr);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            uint L = load_bigEndian!uint(input, 0);
            uint R = load_bigEndian!uint(input, 1);
            
            foreach (size_t j; 0 .. 32)
            {
                R -= (((L << 4) ^ (L >> 5)) + L) ^ m_EK[63 - 2*j];
                L -= (((R << 4) ^ (R >> 5)) + R) ^ m_EK[62 - 2*j];
            }
            
            store_bigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    void clear()
    {
        zap(m_EK);
    }

    override @property string name() const { return "XTEA"; }
    BlockCipher clone() const { return new XTEA; }
protected:
    /**
    * @return const reference to the key schedule
    */
    const Secure_Vector!uint get_EK() const { return m_EK; }

private:
    /*
    * XTEA Key Schedule
    */
    void key_schedule(in ubyte* key, size_t)
    {
        m_EK.resize(64);
        
        Secure_Vector!uint UK = Secure_Vector!uint(4);
        foreach (size_t i; 0 .. 4)
            UK[i] = load_bigEndian!uint(key, i);
        
        uint D = 0;
        foreach (size_t i; iota(0, 64, 2))
        {
            m_EK[i  ] = D + UK[D % 4];
            D += 0x9E3779B9;
            m_EK[i+1] = D + UK[(D >> 11) % 4];
        }
    }

    Secure_Vector!uint m_EK;
}

package:
pure:

void xtea_encrypt_4(in ubyte[32] input, ref ubyte[32] output, in uint[64] EK)
{
    uint L0, R0, L1, R1, L2, R2, L3, R3;
    load_bigEndian(input, L0, R0, L1, R1, L2, R2, L3, R3);
    
    foreach (size_t i; 0 .. 32)
    {
        L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[2*i];
        L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[2*i];
        L2 += (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[2*i];
        L3 += (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[2*i];
        
        R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[2*i+1];
        R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[2*i+1];
        R2 += (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[2*i+1];
        R3 += (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[2*i+1];
    }
    
    store_bigEndian(output, L0, R0, L1, R1, L2, R2, L3, R3);
}

void xtea_decrypt_4(in ubyte[32] input, ref ubyte[32] output, in uint[64] EK)
{
    uint L0, R0, L1, R1, L2, R2, L3, R3;
    load_bigEndian(input, L0, R0, L1, R1, L2, R2, L3, R3);
    
    foreach (size_t i; 0 .. 32)
    {
        R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[63 - 2*i];
        R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[63 - 2*i];
        R2 -= (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[63 - 2*i];
        R3 -= (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[63 - 2*i];
        
        L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[62 - 2*i];
        L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[62 - 2*i];
        L2 -= (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[62 - 2*i];
        L3 -= (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[62 - 2*i];
    }
    
    store_bigEndian(output, L0, R0, L1, R1, L2, R2, L3, R3);
}
