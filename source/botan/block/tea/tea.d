/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.tea;
import botan.loadstor;
/*
* TEA Encryption
*/
void TEA::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	for (size_t i = 0; i != blocks; ++i)
	{
		uint L = load_be!uint(input, 0);
		uint R = load_be!uint(input, 1);

		uint S = 0;
		for (size_t j = 0; j != 32; ++j)
		{
			S += 0x9E3779B9;
			L += ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
			R += ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
		}

		store_be(output, L, R);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* TEA Decryption
*/
void TEA::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	for (size_t i = 0; i != blocks; ++i)
	{
		uint L = load_be!uint(input, 0);
		uint R = load_be!uint(input, 1);

		uint S = 0xC6EF3720;
		for (size_t j = 0; j != 32; ++j)
		{
			R -= ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
			L -= ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
			S -= 0x9E3779B9;
		}

		store_be(output, L, R);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* TEA Key Schedule
*/
void TEA::key_schedule(in byte* key, size_t)
{
	K.resize(4);
	for (size_t i = 0; i != 4; ++i)
		K[i] = load_be!uint(key, i);
}

void TEA::clear()
{
	zap(K);
}

}
