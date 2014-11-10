/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.xtea;

import botan.constants;
static if (BOTAN_HAS_XTEA):

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
		while(blocks >= 4)
		{
			xtea_encrypt_4(input, output, &(m_EK[0]));
			input += 4 * BLOCK_SIZE;
			output += 4 * BLOCK_SIZE;
			blocks -= 4;
		}
		
		for (size_t i = 0; i != blocks; ++i)
		{
			uint L = load_be!uint(input, 0);
			uint R = load_be!uint(input, 1);
			
			for (size_t j = 0; j != 32; ++j)
			{
				L += (((R << 4) ^ (R >> 5)) + R) ^ m_EK[2*j];
				R += (((L << 4) ^ (L >> 5)) + L) ^ m_EK[2*j+1];
			}
			
			store_be(output, L, R);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	
	/*
	* XTEA Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		while(blocks >= 4)
		{
			xtea_decrypt_4(input, output, &(m_EK[0]));
			input += 4 * BLOCK_SIZE;
			output += 4 * BLOCK_SIZE;
			blocks -= 4;
		}
		
		for (size_t i = 0; i != blocks; ++i)
		{
			uint L = load_be!uint(input, 0);
			uint R = load_be!uint(input, 1);
			
			for (size_t j = 0; j != 32; ++j)
			{
				R -= (((L << 4) ^ (L >> 5)) + L) ^ m_EK[63 - 2*j];
				L -= (((R << 4) ^ (R >> 5)) + R) ^ m_EK[62 - 2*j];
			}
			
			store_be(output, L, R);
			
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
	const ref Secure_Vector!uint get_EK() const { return m_EK; }

private:
	/*
	* XTEA Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		m_EK.resize(64);
		
		Secure_Vector!uint UK = Secure_Vector!uint(4);
		for (size_t i = 0; i != 4; ++i)
			UK[i] = load_be!uint(key, i);
		
		uint D = 0;
		for (size_t i = 0; i != 64; i += 2)
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

void xtea_encrypt_4(const ubyte[32]* input, ubyte[32]* output, const uint[64]* EK)
{
	uint L0, R0, L1, R1, L2, R2, L3, R3;
	load_be(input, L0, R0, L1, R1, L2, R2, L3, R3);
	
	for (size_t i = 0; i != 32; ++i)
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
	
	store_be(output, L0, R0, L1, R1, L2, R2, L3, R3);
}

void xtea_decrypt_4(const ubyte[32]* input, ubyte[32]* output, const uint[64]* EK)
{
	uint L0, R0, L1, R1, L2, R2, L3, R3;
	load_be(input, L0, R0, L1, R1, L2, R2, L3, R3);
	
	for (size_t i = 0; i != 32; ++i)
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
	
	store_be(output, L0, R0, L1, R1, L2, R2, L3, R3);
}
