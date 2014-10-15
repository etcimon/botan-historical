/*
* Whirlpool
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash.mdx_hash;
/**
* Whirlpool
*/
class Whirlpool : MDx_HashFunction
{
	public:
		string name() const { return "Whirlpool"; }
		size_t output_length() const { return 64; }
		HashFunction clone() const { return new Whirlpool; }

		void clear();

		Whirlpool() : MDx_HashFunction(64, true, true, 32), M(8), digest(8)
		{ clear(); }
	private:
		void compress_n(in ubyte*, size_t blocks);
		void copy_out(ubyte*);

		static const ulong[256] C0;
		static const ulong[256] C1;
		static const ulong[256] C2;
		static const ulong[256] C3;
		static const ulong[256] C4;
		static const ulong[256] C5;
		static const ulong[256] C6;
		static const ulong[256] C7;

		SafeVector!ulong M, digest;
};