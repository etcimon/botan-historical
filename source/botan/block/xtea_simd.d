/*
* XTEA in SIMD
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.xtea_simd;

import botan.block.xtea;
import botan.utils.loadstor;
import botan.simd.simd_32;

/**
* XTEA implemented using SIMD operations
*/
class XTEA_SIMD : XTEA
{
public:
	size_t parallelism() const { return 8; }

	/*
	* XTEA Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const uint* KS = &(this.get_EK()[0]);
		
		while(blocks >= 8)
		{
			xtea_encrypt_8(input, output, KS);
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
		const uint* KS = &(this.get_EK()[0]);
		
		while(blocks >= 8)
		{
			xtea_decrypt_8(input, output, KS);
			input += 8 * BLOCK_SIZE;
			output += 8 * BLOCK_SIZE;
			blocks -= 8;
		}
		
		if (blocks)
			super.decrypt_n(input, output, blocks);
	}

	BlockCipher clone() const { return new XTEA_SIMD; }
};

package:

void xtea_encrypt_8(const ubyte[64] input, ubyte[64] output, const uint[64] EK)
{
	SIMD_32 L0 = SIMD_32.load_be(input	  );
	SIMD_32 R0 = SIMD_32.load_be(input + 16);
	SIMD_32 L1 = SIMD_32.load_be(input + 32);
	SIMD_32 R1 = SIMD_32.load_be(input + 48);
	
	SIMD_32.transpose(L0, R0, L1, R1);
	
	for (size_t i = 0; i != 32; i += 2)
	{
		SIMD_32 K0(EK[2*i  ]);
		SIMD_32 K1(EK[2*i+1]);
		SIMD_32 K2(EK[2*i+2]);
		SIMD_32 K3(EK[2*i+3]);
		
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
	
	L0.store_be(output);
	R0.store_be(output + 16);
	L1.store_be(output + 32);
	R1.store_be(output + 48);
}

void xtea_decrypt_8(const ubyte[64] input, ubyte[64] output, const uint[64] EK)
{
	SIMD_32 L0 = SIMD_32.load_be(input	  );
	SIMD_32 R0 = SIMD_32.load_be(input + 16);
	SIMD_32 L1 = SIMD_32.load_be(input + 32);
	SIMD_32 R1 = SIMD_32.load_be(input + 48);
	
	SIMD_32.transpose(L0, R0, L1, R1);
	
	for (size_t i = 0; i != 32; i += 2)
	{
		SIMD_32 K0(EK[63 - 2*i]);
		SIMD_32 K1(EK[62 - 2*i]);
		SIMD_32 K2(EK[61 - 2*i]);
		SIMD_32 K3(EK[60 - 2*i]);
		
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
	
	L0.store_be(output);
	R0.store_be(output + 16);
	L1.store_be(output + 32);
	R1.store_be(output + 48);
}
