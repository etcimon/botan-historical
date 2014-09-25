/*
* SHA-160 in x86-32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/sha1_x86_32.h>
namespace {

extern "C"
void botan_sha160_x86_32_compress(u32bit[5], const byte[64], u32bit[81]);

}

/*
* SHA-160 Compression Function
*/
void SHA_160_X86_32::compress_n(const byte input[], size_t blocks)
{
	for(size_t i = 0; i != blocks; ++i)
	{
		botan_sha160_x86_32_compress(&digest[0], input, &W[0]);
		input += hash_block_size();
	}
}

}
