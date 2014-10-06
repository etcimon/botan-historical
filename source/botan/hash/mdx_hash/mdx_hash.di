/*
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
/**
* MDx Hash Function Base Class
*/
class MDx_HashFunction : HashFunction
{
	public:
		/**
		* @param block_length is the number of bytes per block
		* @param big_byte_endian specifies if the hash uses big-endian bytes
		* @param big_bit_endian specifies if the hash uses big-endian bits
		* @param counter_size specifies the size of the counter var in bytes
		*/
		MDx_HashFunction(size_t block_length,
							  bool big_byte_endian,
							  bool big_bit_endian,
							  size_t counter_size = 8);

		size_t hash_block_size() const { return buffer.size(); }
	package:
		void add_data(in ubyte* input, size_t length);
		void final_result(ubyte* output);

		/**
		* Run the hash's compression function over a set of blocks
		* @param blocks the input
		* @param block_n the number of blocks
		*/
		abstract void compress_n(in ubyte* blocks, size_t block_n);

		void clear();

		/**
		* Copy the output to the buffer
		* @param buffer to put the output into
		*/
		abstract void copy_out(ubyte* buffer);

		/**
		* Write the count, if used, to this spot
		* @param out where to write the counter to
		*/
		abstract void write_count(ubyte* output);
	private:
		SafeVector!ubyte buffer;
		ulong count;
		size_t position;

		const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
		const size_t COUNT_SIZE;
};