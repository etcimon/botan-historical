/*
* SHA-160 (x86-64)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.sha160;
/**
* SHA-160 in x86-64 assembly
*/
class SHA_160_X86_64 : public SHA_160
{
	public:
		HashFunction clone() const { return new SHA_160_X86_64; }
	private:
		void compress_n(const ubyte[], size_t blocks);
};