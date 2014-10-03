/*
* RIPEMD-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* RIPEMD-128
*/
class RIPEMD_128 : public MDx_HashFunction
{
	public:
		string name() const { return "RIPEMD-128"; }
		size_t output_length() const { return 16; }
		HashFunction clone() const { return new RIPEMD_128; }

		void clear();

		RIPEMD_128() : MDx_HashFunction(64, false, true), M(16), digest(4)
		{ clear(); }
	private:
		void compress_n(const byte*, size_t blocks);
		void copy_out(byte*);

		secure_vector!uint M, digest;
};