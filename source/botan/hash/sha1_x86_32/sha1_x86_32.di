/*
* SHA-160 in x86-32 asm
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/sha160.h>
/**
* SHA-160 in x86 assembly
*/
class SHA_160_X86_32 : public SHA_160
{
	public:
		HashFunction* clone() const { return new SHA_160_X86_32; }

		// Note 81 instead of normal 80: x86-32 asm needs an extra temp
		SHA_160_X86_32() : SHA_160(81) {}
	private:
		void compress_n(const byte[], size_t blocks);
};