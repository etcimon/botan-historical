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
		m_buffer = block_len;
		m_BIG_BYTE_ENDIAN = byte_end;
		m_BIG_BIT_ENDIAN = bit_end;
		m_COUNT_SIZE = cnt_size;
		m_count = m_position = 0;
	}

	final override @property size_t hash_block_size() const { return m_buffer.length; }
protected:
	/*
	* Update the hash
	*/
	final void add_data(in ubyte* input, size_t length)
	{
		m_count += length;
		
		if (m_position)
		{
			buffer_insert(m_buffer, m_position, input, length);
			
			if (m_position + length >= m_buffer.length)
			{
				compress_n(&m_buffer[0], 1);
				input += (m_buffer.length - m_position);
				length -= (m_buffer.length - m_position);
				m_position = 0;
			}
		}
		
		const size_t full_blocks = length / m_buffer.length;
		const size_t remaining	= length % m_buffer.length;
		
		if (full_blocks)
			compress_n(input, full_blocks);
		
		buffer_insert(m_buffer, m_position, input + full_blocks * m_buffer.length, remaining);
		m_position += remaining;
	}


	/*
	* Finalize a hash
	*/
	final void final_result(ubyte* output)
	{
		m_buffer[m_position] = (m_BIG_BIT_ENDIAN ? 0x80 : 0x01);
		for (size_t i = m_position+1; i != m_buffer.length; ++i)
			m_buffer[i] = 0;
		
		if (m_position >= m_buffer.length - m_COUNT_SIZE)
		{
			compress_n(&m_buffer[0], 1);
			zeroise(m_buffer);
		}
		
		write_count(&m_buffer[m_buffer.length - m_COUNT_SIZE]);
		
		compress_n(&m_buffer[0], 1);
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
	final void clear()
	{
		zeroise(m_buffer);
		m_count = m_position = 0;
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
	final void write_count(ubyte* output)
	{
		if (m_COUNT_SIZE < 8)
			throw new Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");
		if (m_COUNT_SIZE >= output_length() || m_COUNT_SIZE >= hash_block_size)
			throw new Invalid_Argument("MDx_HashFunction: COUNT_SIZE is too big");
		
		const ulong bit_count = m_count * 8;
		
		if (m_BIG_BYTE_ENDIAN)
			store_be(bit_count, output + m_COUNT_SIZE - 8);
		else
			store_le(bit_count, output + m_COUNT_SIZE - 8);
	}
private:
	Secure_Vector!ubyte m_buffer;
	ulong m_count;
	size_t m_position;

	const bool m_BIG_BYTE_ENDIAN, m_BIG_BIT_ENDIAN;
	const size_t m_COUNT_SIZE;
}