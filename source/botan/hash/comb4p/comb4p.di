/*
* Comb4P hash combiner
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/hash.h>
/**
* Combines two hash functions using a Feistel scheme. Described in
* "On the Security of Hash Function Combiners", Anja Lehmann
*/
class Comb4P : public HashFunction
{
	public:
		/**
		* @param h1 the first hash
		* @param h2 the second hash
		*/
		Comb4P(HashFunction* h1, HashFunction* h2);

		size_t hash_block_size() const;

		size_t output_length() const
		{
			return m_hash1->output_length() + m_hash2->output_length();
		}

		HashFunction* clone() const
		{
			return new Comb4P(m_hash1->clone(), m_hash2->clone());
		}

		string name() const
		{
			return "Comb4P(" + m_hash1->name() + "," + m_hash2->name() + ")";
		}

		void clear();
	private:
		void add_data(in byte[] input, size_t length);
		void final_result(ref byte[] output);

		std::unique_ptr<HashFunction> m_hash1, m_hash2;
};