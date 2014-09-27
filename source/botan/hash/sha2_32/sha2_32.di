/*
* SHA-{224,256}
* (C) 1999-2011 Jack Lloyd
*	  2007 FlexSecure GmbH
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* SHA-224
*/
class SHA_224 : public MDx_HashFunction
{
	public:
		string name() const { return "SHA-224"; }
		size_t output_length() const { return 28; }
		HashFunction* clone() const { return new SHA_224; }

		void clear();

		SHA_224() : MDx_HashFunction(64, true, true), digest(8)
		{ clear(); }
	private:
		void compress_n(const byte[], size_t blocks);
		void copy_out(byte[]);

		secure_vector!uint digest;
};

/**
* SHA-256
*/
class SHA_256 : public MDx_HashFunction
{
	public:
		string name() const { return "SHA-256"; }
		size_t output_length() const { return 32; }
		HashFunction* clone() const { return new SHA_256; }

		void clear();

		SHA_256() : MDx_HashFunction(64, true, true), digest(8)
		{ clear(); }
	private:
		void compress_n(const byte[], size_t blocks);
		void copy_out(byte[]);

		secure_vector!uint digest;
};