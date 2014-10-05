/*
* MD4 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.md4_x86_32;
/**
* MD4 compression function in x86-32 asm
* @param digest the current digest
* @param input the input block
* @param M the message buffer
*/
extern "C" void botan_md4_x86_32_compress(uint digest[4],
													 const ubyte input[64],
													 uint M[16]);

/*
* MD4 Compression Function
*/
void MD4_X86_32::compress_n(in ubyte* input, size_t blocks)
{
	for (size_t i = 0; i != blocks; ++i)
	{
		botan_md4_x86_32_compress(&digest[0], input, &M[0]);
		input += hash_block_size();
	}
}

}
