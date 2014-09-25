/*
* MD2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/hash.h>
/**
* MD2
*/
class MD2 : public HashFunction
{
	public:
		string name() const { return "MD2"; }
		size_t output_length() const { return 16; }
		size_t hash_block_size() const { return 16; }
		HashFunction* clone() const { return new MD2; }

		void clear();

		MD2() : X(48), checksum(16), buffer(16)
		{ clear(); }
	private:
		void add_data(const byte[], size_t);
		void hash(const byte[]);
		void final_result(byte[]);

		SafeVector!byte X, checksum, buffer;
		size_t position;
};