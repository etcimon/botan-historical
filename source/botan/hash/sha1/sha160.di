/*
* SHA-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mdx_hash;
/**
* NIST's SHA-160
*/
class SHA_160 : public MDx_HashFunction
{
	public:
		string name() const { return "SHA-160"; }
		size_t output_length() const { return 20; }
		HashFunction clone() const { return new SHA_160; }

		void clear();

		SHA_160() : MDx_HashFunction(64, true, true), digest(5), W(80)
		{
			clear();
		}
	package:
		/**
		* Set a custom size for the W array. Normally 80, but some
		* subclasses need slightly more for best performance/internal
		* constraints
		* @param W_size how big to make W
		*/
		SHA_160(size_t W_size) :
			MDx_HashFunction(64, true, true), digest(5), W(W_size)
		{
			clear();
		}

		void compress_n(const byte[], size_t blocks);
		void copy_out(byte[]);

		/**
		* The digest value, exposed for use by subclasses (asm, SSE2)
		*/
		secure_vector!uint digest;

		/**
		* The message buffer, exposed for use by subclasses (asm, SSE2)
		*/
		secure_vector!uint W;
};