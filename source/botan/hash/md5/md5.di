/*
* MD5
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* MD5
*/
class MD5 : public MDx_HashFunction
{
	public:
		string name() const { return "MD5"; }
		size_t output_length() const { return 16; }
		HashFunction clone() const { return new MD5; }

		void clear();

		MD5() : MDx_HashFunction(64, false, true), M(16), digest(4)
		{ clear(); }
	package:
		void compress_n(const byte[], size_t blocks);
		void copy_out(byte[]);

		/**
		* The message buffer, exposed for use by subclasses (x86 asm)
		*/
		secure_vector!uint M;

		/**
		* The digest value, exposed for use by subclasses (x86 asm)
		*/
		secure_vector!uint digest;
};