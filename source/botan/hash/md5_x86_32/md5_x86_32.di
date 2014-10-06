/*
* MD5 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.md5;
/**
* MD5 in x86 assembly
*/
class MD5_X86_32 : MD5
{
	public:
		HashFunction clone() const { return new MD5_X86_32; }
	private:
		void compress_n(const ubyte[], size_t blocks);
};