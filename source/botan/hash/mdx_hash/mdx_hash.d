/*
* Merkle-Damgard Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.mdx_hash;
import botan.exceptn;
import botan.loadstor;
/*
* MDx_HashFunction Constructor
*/
MDx_HashFunction::MDx_HashFunction(size_t block_len,
									  bool byte_end,
									  bool bit_end,
									  size_t cnt_size) :
	buffer(block_len),
	BIG_BYTE_ENDIAN(byte_end),
	BIG_BIT_ENDIAN(bit_end),
	COUNT_SIZE(cnt_size)
{
	count = position = 0;
}

/*
* Clear memory of sensitive data
*/
void MDx_HashFunction::clear()
{
	zeroise(buffer);
	count = position = 0;
}

/*
* Update the hash
*/
void MDx_HashFunction::add_data(in ubyte* input, size_t length)
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
void MDx_HashFunction::final_result(ubyte* output)
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

/*
* Write the count bits to the buffer
*/
void MDx_HashFunction::write_count(ubyte* output)
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

}
