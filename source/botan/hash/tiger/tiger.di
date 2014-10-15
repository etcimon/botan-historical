/*
* Tiger
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash.mdx_hash;
/**
* Tiger
*/
class Tiger : MDx_HashFunction
{
	public:
		string name() const;
		size_t output_length() const { return hash_len; }

		HashFunction clone() const
		{
			return new Tiger(output_length(), passes);
		}

		void clear();

		/**
		* @param out_size specifies the output length; can be 16, 20, or 24
		* @param passes to make in the algorithm
		*/
		Tiger(size_t out_size = 24, size_t passes = 3);
	private:
		void compress_n(const ubyte[], size_t block);
		void copy_out(ubyte[]);

		static void pass(ref ulong A, ref ulong B, ref ulong C,
							  const SafeVector!ulong& M,
							  ubyte mul);

		static const ulong SBOX1[256];
		static const ulong SBOX2[256];
		static const ulong SBOX3[256];
		static const ulong SBOX4[256];

		SafeVector!ulong X, digest;
		const size_t hash_len, passes;
};