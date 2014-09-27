/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.desx;
import botan.internal.xor_buf;
/*
* DESX Encryption
*/
void DESX::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	for (size_t i = 0; i != blocks; ++i)
	{
		xor_buf(output, input, &K1[0], BLOCK_SIZE);
		des.encrypt(output);
		xor_buf(output, &K2[0], BLOCK_SIZE);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* DESX Decryption
*/
void DESX::decrypt_n(byte* input, byte* output, size_t blocks) const
{	
	for (size_t i = 0; i != blocks; ++i)
	{
		xor_buf(output, input, &K2[0], BLOCK_SIZE);
		des.decrypt(output);
		xor_buf(output, &K1[0], BLOCK_SIZE);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* DESX Key Schedule
*/
void DESX::key_schedule(in byte* key, size_t)
{
	K1.assign(key, key + 8);
	des.set_key(key + 8, 8);
	K2.assign(key + 16, key + 24);
}

void DESX::clear()
{
	des.clear();
	zap(K1);
	zap(K2);
}
