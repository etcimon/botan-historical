/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.noekeon;

import botan.constants;
static if (BOTAN_HAS_NOEKEON):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;

/**
* Noekeon
*/
class Noekeon : Block_Cipher_Fixed_Params!(16, 16)
{
public:
    /*
    * Noekeon Encryption
    */
    void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A0 = load_be!uint(input, 0);
            uint A1 = load_be!uint(input, 1);
            uint A2 = load_be!uint(input, 2);
            uint A3 = load_be!uint(input, 3);
            
            foreach (size_t j; 0 .. 16)
            {
                A0 ^= m_RC[j];
                theta(A0, A1, A2, A3, m_EK.ptr);
                
                A1 = rotate_left(A1, 1);
                A2 = rotate_left(A2, 5);
                A3 = rotate_left(A3, 2);
                
                gamma(A0, A1, A2, A3);
                
                A1 = rotate_right(A1, 1);
                A2 = rotate_right(A2, 5);
                A3 = rotate_right(A3, 2);
            }
            
            A0 ^= m_RC[16];
            theta(A0, A1, A2, A3, m_EK.ptr);
            
            store_be(output, A0, A1, A2, A3);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * Noekeon Encryption
    */
    void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A0 = load_be!uint(input, 0);
            uint A1 = load_be!uint(input, 1);
            uint A2 = load_be!uint(input, 2);
            uint A3 = load_be!uint(input, 3);
            
            for (size_t j = 16; j != 0; --j)
            {
                theta(A0, A1, A2, A3, m_DK.ptr);
                A0 ^= m_RC[j];
                
                A1 = rotate_left(A1, 1);
                A2 = rotate_left(A2, 5);
                A3 = rotate_left(A3, 2);
                
                gamma(A0, A1, A2, A3);
                
                A1 = rotate_right(A1, 1);
                A2 = rotate_right(A2, 5);
                A3 = rotate_right(A3, 2);
            }
            
            theta(A0, A1, A2, A3, m_DK.ptr);
            A0 ^= m_RC[0];
            
            store_be(output, A0, A1, A2, A3);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }
    

    @property string name() const { return "Noekeon"; }
    BlockCipher clone() const { return new Noekeon; }

protected:
    /**
    * The Noekeon round constants
    */
    __gshared immutable ubyte[17] m_RC = [
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4 ];

    /**
    * @return const reference to encryption subkeys
    */
    const Secure_Vector!uint get_EK() const { return m_EK; }

    /**
    * @return const reference to decryption subkeys
    */
    const Secure_Vector!uint get_DK() const { return m_DK; }

private:
    /*
    * Noekeon Key Schedule
    */
    void key_schedule(in ubyte* key, size_t)
    {
        uint A0 = load_be!uint(key, 0);
        uint A1 = load_be!uint(key, 1);
        uint A2 = load_be!uint(key, 2);
        uint A3 = load_be!uint(key, 3);
        
        foreach (size_t i; 0 .. 16)
        {
            A0 ^= m_RC[i];
            theta(A0, A1, A2, A3);
            
            A1 = rotate_left(A1, 1);
            A2 = rotate_left(A2, 5);
            A3 = rotate_left(A3, 2);
            
            gamma(A0, A1, A2, A3);
            
            A1 = rotate_right(A1, 1);
            A2 = rotate_right(A2, 5);
            A3 = rotate_right(A3, 2);
        }
        
        A0 ^= m_RC[16];
        
        m_DK.resize(4);
        m_DK[0] = A0;
        m_DK[1] = A1;
        m_DK[2] = A2;
        m_DK[3] = A3;
        
        theta(A0, A1, A2, A3);
        
        m_EK.resize(4);
        m_EK[0] = A0;
        m_EK[1] = A1;
        m_EK[2] = A2;
        m_EK[3] = A3;
    }

    Secure_Vector!uint m_EK, m_DK;
}

package:
    
/*
* Noekeon's Theta Operation
*/
void theta(ref uint A0, ref uint A1,
           ref uint A2, ref uint A3,
           in uint EK[4]) pure
{
    uint T = A0 ^ A2;
    T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
    A1 ^= T;
    A3 ^= T;
    
    A0 ^= EK[0];
    A1 ^= EK[1];
    A2 ^= EK[2];
    A3 ^= EK[3];
    
    T = A1 ^ A3;
    T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
    A0 ^= T;
    A2 ^= T;
}

/*
* Theta With Null Key
*/
void theta(ref uint A0, ref uint A1,
           ref uint A2, ref uint A3) pure
{
    uint T = A0 ^ A2;
    T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
    A1 ^= T;
    A3 ^= T;
    
    T = A1 ^ A3;
    T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
    A0 ^= T;
    A2 ^= T;
}

/*
* Noekeon's Gamma S-Box Layer
*/
void gamma(ref uint A0, ref uint A1, ref uint A2, ref uint A3) pure
{
    A1 ^= ~A3 & ~A2;
    A0 ^= A2 & A1;
    
    uint T = A3;
    A3 = A0;
    A0 = T;
    
    A2 ^= A0 ^ A1 ^ A3;
    
    A1 ^= ~A3 & ~A2;
    A0 ^= A2 & A1;
}
