/*
* Parallel Hash
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
import vector;
/**
* Parallel Hashes
*/
class Parallel : HashFunction
{
	public:
		void clear();
		string name() const;
		HashFunction clone() const;

		size_t output_length() const;

		/**
		* @param hashes a set of hashes to compute in parallel
		*/
		Parallel(in Vector!( HashFunction ) hashes);
		~this();
	private:
		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);
		Vector!( HashFunction ) hashes;
};