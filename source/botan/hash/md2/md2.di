/*
* MD2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
/**
* MD2
*/
class MD2 : HashFunction
{
	public:
		string name() const { return "MD2"; }
		size_t output_length() const { return 16; }
		size_t hash_block_size() const { return 16; }
		HashFunction clone() const { return new MD2; }

		void clear();

		MD2() : X(48), checksum(16), buffer(16)
		{ clear(); }
	private:
		void add_data(const ubyte[], size_t);
		void hash(const ubyte[]);
		void final_result(ubyte[]);

		SafeVector!ubyte X, checksum, buffer;
		size_t position;
};