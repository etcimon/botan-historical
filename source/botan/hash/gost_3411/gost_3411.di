/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
import botan.gost_28147;
/**
* GOST 34.11
*/
class GOST_34_11 : HashFunction
{
	public:
		string name() const { return "GOST-R-34.11-94" ; }
		size_t output_length() const { return 32; }
		size_t hash_block_size() const { return 32; }
		HashFunction clone() const { return new GOST_34_11; }

		void clear();

		GOST_34_11();
	private:
		void compress_n(in ubyte* input, size_t blocks);

		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);

		GOST_28147_89 cipher;
		SafeVector!ubyte buffer, sum, hash;
		size_t position;
		ulong count;
};