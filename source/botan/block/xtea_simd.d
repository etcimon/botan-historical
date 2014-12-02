/*
* XTEA in SIMD
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.xtea_simd;

import botan.constants;
static if (BOTAN_HAS_XTEA_SIMD):


import botan.block.xtea;
import botan.utils.loadstor;
import botan.simd.simd_32;
import std.range : iota;

/**
* XTEA implemented using SIMD operations
*/
final class XTEA_SIMD : XTEA
{
public:
    override @property size_t parallelism() const { return 8; }

    /*
    * XTEA Encryption
    */
    void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        const uint* KS = this.get_EK().ptr;
        
        while (blocks >= 8)
        {
            xtea_encrypt_8(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(uint[64]*) KS);
            input += 8 * BLOCK_SIZE;
            output += 8 * BLOCK_SIZE;
            blocks -= 8;
        }
        
        if (blocks)
            super.encrypt_n(input, output, blocks);
    }

    /*
    * XTEA Decryption
    */
    void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
    {
        const uint* KS = this.get_EK().ptr;
        
        while (blocks >= 8)
        {
            xtea_decrypt_8(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(uint[64]*) KS);
            input += 8 * BLOCK_SIZE;
            output += 8 * BLOCK_SIZE;
            blocks -= 8;
        }
        
        if (blocks)
            super.decrypt_n(input, output, blocks);
    }

    BlockCipher clone() const { return new XTEA_SIMD; }
}

package:

void xtea_encrypt_8(in ubyte[64] input, ref ubyte[64] output, in uint[64] EK) pure
{
    SIMD_32 L0 = SIMD_32.load_bigEndian(input.ptr      );
    SIMD_32 R0 = SIMD_32.load_bigEndian(input.ptr + 16);
    SIMD_32 L1 = SIMD_32.load_bigEndian(input.ptr + 32);
    SIMD_32 R1 = SIMD_32.load_bigEndian(input.ptr + 48);

    SIMD_32.transpose(L0, R0, L1, R1);
    
    foreach (size_t i; iota(0, 32, 2))
    {
        SIMD_32 K0 = SIMD_32(EK[2*i  ]);
        SIMD_32 K1 = SIMD_32(EK[2*i+1]);
        SIMD_32 K2 = SIMD_32(EK[2*i+2]);
        SIMD_32 K3 = SIMD_32(EK[2*i+3]);
        
        L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K0;
        L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K0;
        
        R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K1;
        R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K1;
        
        L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K2;
        L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K2;
        
        R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K3;
        R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K3;
    }
    
    SIMD_32.transpose(L0, R0, L1, R1);
    
    L0.store_bigEndian(output.ptr);
    R0.store_bigEndian(output.ptr + 16);
    L1.store_bigEndian(output.ptr + 32);
    R1.store_bigEndian(output.ptr + 48);
}

void xtea_decrypt_8(in ubyte[64] input, ref ubyte[64] output, in uint[64] EK)
{
    SIMD_32 L0 = SIMD_32.load_bigEndian(input.ptr      );
    SIMD_32 R0 = SIMD_32.load_bigEndian(input.ptr + 16);
    SIMD_32 L1 = SIMD_32.load_bigEndian(input.ptr + 32);
    SIMD_32 R1 = SIMD_32.load_bigEndian(input.ptr + 48);

    SIMD_32.transpose(L0, R0, L1, R1);
    
    foreach (size_t i; iota(0, 32, 2))
    {
        SIMD_32 K0 = SIMD_32(EK[63 - 2*i]);
        SIMD_32 K1 = SIMD_32(EK[62 - 2*i]);
        SIMD_32 K2 = SIMD_32(EK[61 - 2*i]);
        SIMD_32 K3 = SIMD_32(EK[60 - 2*i]);
        
        R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K0;
        R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K0;
        
        L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K1;
        L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K1;
        
        R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K2;
        R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K2;
        
        L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K3;
        L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K3;
    }
    
    SIMD_32.transpose(L0, R0, L1, R1);
    
    L0.store_bigEndian(output.ptr);
    R0.store_bigEndian(output.ptr + 16);
    L1.store_bigEndian(output.ptr + 32);
    R1.store_bigEndian(output.ptr + 48);
}
