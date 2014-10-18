/*
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.mdx_hash;

import botan.hash.hash;
import botan.hash.mdx_hash;
import botan.utils.exceptn;
import botan.utils.loadstor;

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
	this(size_t block_len,
	     bool byte_end,
	     bool bit_end,
	     size_t cnt_size = 0)
	{
		buffer = block_len;
		BIG_BYTE_ENDIAN = byte_end;
		BIG_BIT_ENDIAN = bit_end;
		COUNT_SIZE = cnt_size;
		count = position = 0;
	}

	size_t hash_block_size() const { return buffer.size(); }
package:
	/*
	* Update the hash
	*/
	void add_data(in ubyte* input, size_t length)
	{
		count += length;
		
		if (position)
		{
			buffer_insert(buffer, position, input, length);
			
			if (position + length >= buffer.size())
			{
				compress_n(&buffer[0], 1);
				input += (buffer.size() - position);
				length -= (buffer.size() - position);
				position = 0;
			}
		}
		
		const size_t full_blocks = length / buffer.size();
		const size_t remaining	= length % buffer.size();
		
		if (full_blocks)
			compress_n(input, full_blocks);
		
		buffer_insert(buffer, position, input + full_blocks * buffer.size(), remaining);
		position += remaining;
	}


	/*
	* Finalize a hash
	*/
	void final_result(ubyte* output)
	{
		buffer[position] = (BIG_BIT_ENDIAN ? 0x80 : 0x01);
		for (size_t i = position+1; i != buffer.size(); ++i)
			buffer[i] = 0;
		
		if (position >= buffer.size() - COUNT_SIZE)
		{
			compress_n(&buffer[0], 1);
			zeroise(buffer);
		}
		
		write_count(&buffer[buffer.size() - COUNT_SIZE]);
		
		compress_n(&buffer[0], 1);
		copy_out(output);
		clear();
	}

	/**
	* Run the hash's compression function over a set of blocks
	* @param blocks the input
	* @param block_n the number of blocks
	*/
	abstract void compress_n(in ubyte* blocks, size_t block_n);

	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		zeroise(buffer);
		count = position = 0;
	}

	/**
	* Copy the output to the buffer
	* @param buffer to put the output into
	*/
	abstract void copy_out(ubyte* buffer);

	/**
	* Write the count, if used, to this spot
	* @param output where to write the counter to
	*/
	void write_count(ubyte* output)
	{
		if (COUNT_SIZE < 8)
			throw new Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");
		if (COUNT_SIZE >= output_length() || COUNT_SIZE >= hash_block_size())
			throw new Invalid_Argument("MDx_HashFunction: COUNT_SIZE is too big");
		
		const ulong bit_count = count * 8;
		
		if (BIG_BYTE_ENDIAN)
			store_be(bit_count, output + COUNT_SIZE - 8);
		else
			store_le(bit_count, output + COUNT_SIZE - 8);
	}
private:
	SafeVector!ubyte buffer;
	ulong count;
	size_t position;

	const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
	const size_t COUNT_SIZE;
};