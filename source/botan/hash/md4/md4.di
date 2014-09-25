/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_MD4_H__

#include <botan/mdx_hash.h>
/**
* MD4
*/
class MD4 : public MDx_HashFunction
{
	public:
		string name() const { return "MD4"; }
		size_t output_length() const { return 16; }
		HashFunction* clone() const { return new MD4; }

		void clear();

		MD4() : MDx_HashFunction(64, false, true), M(16), digest(4)
		{ clear(); }
	protected:
		void compress_n(const byte input[], size_t blocks);
		void copy_out(byte[]);

		/**
		* The message buffer, exposed for use by subclasses (x86 asm)
		*/
		secure_vector<u32bit> M;

		/**
		* The digest value, exposed for use by subclasses (x86 asm)
		*/
		secure_vector<u32bit> digest;
};