/*
* MD4 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.md4;
/**
* MD4 using x86 assembly
*/
class MD4_X86_32 : public MD4
{
	public:
		HashFunction* clone() const { return new MD4_X86_32; }
	private:
		void compress_n(const byte[], size_t blocks);
};