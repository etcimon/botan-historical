/*
* Keccak
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/hash.h>
#include <botan/secmem.h>
#include <string>
/**
* Keccak[1600], a SHA-3 candidate
*/
class Keccak_1600 : public HashFunction
{
	public:

		/**
		* @param output_bits the size of the hash output; must be one of
		*						  224, 256, 384, or 512
		*/
		Keccak_1600(size_t output_bits = 512);

		size_t hash_block_size() const { return bitrate / 8; }
		size_t output_length() const { return output_bits / 8; }

		HashFunction* clone() const;
		string name() const;
		void clear();
	private:
		void add_data(in byte[] input, size_t length);
		void final_result(ref byte[] output);

		size_t output_bits, bitrate;
		secure_vector<u64bit> S;
		size_t S_pos;
};