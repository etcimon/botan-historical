/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/hash.h>
#include <botan/gost_28147.h>
/**
* GOST 34.11
*/
class GOST_34_11 : public HashFunction
{
	public:
		string name() const { return "GOST-R-34.11-94" ; }
		size_t output_length() const { return 32; }
		size_t hash_block_size() const { return 32; }
		HashFunction* clone() const { return new GOST_34_11; }

		void clear();

		GOST_34_11();
	private:
		void compress_n(in byte[] input, size_t blocks);

		void add_data(const byte[], size_t);
		void final_result(byte[]);

		GOST_28147_89 cipher;
		SafeVector!byte buffer, sum, hash;
		size_t position;
		u64bit count;
};