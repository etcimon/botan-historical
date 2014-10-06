/*
* SHA-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.sha160;
/**
* SHA-160 using SSE2 for the message expansion
*/
class SHA_160_SSE2 : SHA_160
{
	public:
		HashFunction clone() const { return new SHA_160_SSE2; }
		SHA_160_SSE2() : SHA_160(0) {} // no W needed
	private:
		void compress_n(const ubyte[], size_t blocks);
};