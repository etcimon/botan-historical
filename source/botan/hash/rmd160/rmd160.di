/*
* RIPEMD-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* RIPEMD-160
*/
class RIPEMD_160 : public MDx_HashFunction
{
	public:
		string name() const { return "RIPEMD-160"; }
		size_t output_length() const { return 20; }
		HashFunction clone() const { return new RIPEMD_160; }

		void clear();

		RIPEMD_160() : MDx_HashFunction(64, false, true), M(16), digest(5)
		{ clear(); }
	private:
		void compress_n(const ubyte[], size_t blocks);
		void copy_out(ubyte[]);

		secure_vector!uint M, digest;
};