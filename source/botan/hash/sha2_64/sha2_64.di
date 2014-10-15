/*
* SHA-{384,512}
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash.mdx_hash;
/**
* SHA-384
*/
class SHA_384 : MDx_HashFunction
{
	public:
		string name() const { return "SHA-384"; }
		size_t output_length() const { return 48; }
		HashFunction clone() const { return new SHA_384; }

		void clear();

		SHA_384() : MDx_HashFunction(128, true, true, 16), digest(8)
		{ clear(); }
	private:
		void compress_n(const ubyte[], size_t blocks);
		void copy_out(ubyte[]);

		SafeVector!ulong digest;
};

/**
* SHA-512
*/
class SHA_512 : MDx_HashFunction
{
	public:
		string name() const { return "SHA-512"; }
		size_t output_length() const { return 64; }
		HashFunction clone() const { return new SHA_512; }

		void clear();

		SHA_512() : MDx_HashFunction(128, true, true, 16), digest(8)
		{ clear(); }
	private:
		void compress_n(const ubyte[], size_t blocks);
		void copy_out(ubyte[]);

		SafeVector!ulong digest;
};