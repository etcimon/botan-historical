/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/desx.h>
#include <botan/internal/xor_buf.h>
/*
* DESX Encryption
*/
void DESX::encrypt_n(in byte[] input, ref byte[] output) const
{
	for(size_t i = 0; i != blocks; ++i)
	{
		xor_buf(out, in, &K1[0], BLOCK_SIZE);
		des.encrypt(out);
		xor_buf(out, &K2[0], BLOCK_SIZE);

		in += BLOCK_SIZE;
		out += BLOCK_SIZE;
	}
}

/*
* DESX Decryption
*/
void DESX::decrypt_n(in byte[] input, ref byte[] output) const
{
	for(size_t i = 0; i != blocks; ++i)
	{
		xor_buf(out, in, &K2[0], BLOCK_SIZE);
		des.decrypt(out);
		xor_buf(out, &K1[0], BLOCK_SIZE);

		in += BLOCK_SIZE;
		out += BLOCK_SIZE;
	}
}

/*
* DESX Key Schedule
*/
void DESX::key_schedule(in byte[] key, size_t)
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

}
