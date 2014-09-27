/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
import botan.hash;
/**
* EMSA1 from IEEE 1363
* Essentially, sign the hash directly
*/
class EMSA1 : public EMSA
{
	public:
		/**
		* @param hash the hash function to use
		*/
		EMSA1(HashFunction* hash) : m_hash(hash) {}

	protected:
		size_t hash_output_length() const { return m_hash->output_length(); }
	private:
		void update(const byte[], size_t);
		SafeVector!byte raw_data();

		SafeVector!byte encoding_of(in SafeVector!byte msg,
												  size_t output_bits,
												  RandomNumberGenerator& rng);

		bool verify(in SafeVector!byte coded,
						in SafeVector!byte raw,
						size_t key_bits);

		Unique!HashFunction m_hash;
};