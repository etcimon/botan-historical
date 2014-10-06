/*
* HAS-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* HAS-160, a Korean hash function standardized in
* TTAS.KO-12.0011/R1. Used in conjuction with KCDSA
*/
class HAS_160 : MDx_HashFunction
{
	public:
		string name() const { return "HAS-160"; }
		size_t output_length() const { return 20; }
		HashFunction clone() const { return new HAS_160; }

		void clear();

		HAS_160() : MDx_HashFunction(64, false, true), X(20), digest(5)
		{ clear(); }
	private:
		void compress_n(const ubyte[], size_t blocks);
		void copy_out(ubyte[]);

		secure_vector!uint X, digest;
};