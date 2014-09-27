/*
* XTEA
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xtea.h>
#include <botan/loadstor.h>
namespace {

void xtea_encrypt_4(const byte[32] input, byte[32] output, const uint[64] EK)
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

void xtea_decrypt_4(const byte[32] input, byte[32] output, const uint[64] EK)
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

}

/*
* XTEA Encryption
*/
void XTEA::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	while(blocks >= 4)
	{
		xtea_encrypt_4(input, output, &(this->EK[0]));
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
			L += (((R << 4) ^ (R >> 5)) + R) ^ EK[2*j];
			R += (((L << 4) ^ (L >> 5)) + L) ^ EK[2*j+1];
		}

		store_be(output, L, R);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* XTEA Decryption
*/
void XTEA::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	while(blocks >= 4)
	{
		xtea_decrypt_4(input, output, &(this->EK[0]));
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
			R -= (((L << 4) ^ (L >> 5)) + L) ^ EK[63 - 2*j];
			L -= (((R << 4) ^ (R >> 5)) + R) ^ EK[62 - 2*j];
		}

		store_be(output, L, R);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* XTEA Key Schedule
*/
void XTEA::key_schedule(in byte* key, size_t)
{
	EK.resize(64);

	secure_vector<uint> UK(4);
	for (size_t i = 0; i != 4; ++i)
		UK[i] = load_be!uint(key, i);

	uint D = 0;
	for (size_t i = 0; i != 64; i += 2)
	{
		EK[i  ] = D + UK[D % 4];
		D += 0x9E3779B9;
		EK[i+1] = D + UK[(D >> 11) % 4];
	}
}

void XTEA::clear()
{
	zap(EK);
}

}
