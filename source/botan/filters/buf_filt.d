/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.buf_filt;

import botan.utils.memory.zeroize;

import botan.utils.mem_ops;
import botan.utils.rounding;
import std.exception;

/**
* Filter mixin that breaks input into blocks, useful for
* cipher modes
*/
class Buffered_Filter
{
public:
	/**
	* Write bytes into the buffered filter, which will them emit them
	* in calls to buffered_block in the subclass
	* @param input the input bytes
	* @param input_size of input in bytes
	*/
	void write(in ubyte* input, size_t input_size)
	{
		if (!input_size)
			return;
		
		if (m_buffer_pos + input_size >= m_main_block_mod + m_final_minimum)
		{
			size_t to_copy = std.algorithm.min(m_buffer.length - m_buffer_pos, input_size);
			
			copy_mem(&m_buffer[m_buffer_pos], input, to_copy);
			m_buffer_pos += to_copy;
			
			input += to_copy;
			input_size -= to_copy;
			
			size_t total_to_consume = round_down(std.algorithm.min(m_buffer_pos,
			                                     m_buffer_pos + input_size - m_final_minimum),
			                                     m_main_block_mod);
			
			buffered_block(m_buffer.ptr, total_to_consume);
			
			m_buffer_pos -= total_to_consume;
			
			copy_mem(m_buffer.ptr, m_buffer.ptr + total_to_consume, buffer_pos);
		}
		
		if (input_size >= m_final_minimum)
		{
			size_t full_blocks = (input_size - m_final_minimum) / m_main_block_mod;
			size_t to_copy = full_blocks * m_main_block_mod;
			
			if (to_copy)
			{
				buffered_block(input, to_copy);
				
				input += to_copy;
				input_size -= to_copy;
			}
		}
		
		copy_mem(&m_buffer[buffer_pos], input, input_size);
		m_buffer_pos += input_size;
	}

	void write(Alloc)(in Vector!( ubyte, Alloc ) input)
	{
		write(input.ptr, input.length);
	}

	/**
	* Finish a message, emitting to buffered_block and buffered_final
	* Will throw new an exception if less than final_minimum bytes were
	* written into the filter.
	*/
	void end_msg()
	{
		if (m_buffer_pos < m_final_minimum)
			throw new Exception("Buffered filter end_msg without enough input");
		
		size_t spare_blocks = (m_buffer_pos - m_final_minimum) / m_main_block_mod;
		
		if (spare_blocks)
		{
			size_t spare_bytes = m_main_block_mod * spare_blocks;
			buffered_block(m_buffer.ptr, spare_bytes);
			buffered_final(&m_buffer[spare_bytes], m_buffer_pos - spare_bytes);
		}
		else
		{
			buffered_final(m_buffer.ptr, m_buffer_pos);
		}
		
		m_buffer_pos = 0;
	}

	/**
	* Initialize a Buffered_Filter
	* @param block_size the function buffered_block will be called
	*		  with inputs which are a multiple of this size
	* @param final_minimum the function buffered_final will be called
	*		  with at least this many bytes.
	*/
	this(size_t block_size, size_t final_minimum)
	{
		
		m_main_block_mod = block_size;
		m_final_minimum = final_minimum;
		
		if (m_main_block_mod == 0)
			throw new Invalid_Argument("main_block_mod == 0");
		
		if (m_final_minimum > m_main_block_mod)
			throw new Invalid_Argument("final_minimum > main_block_mod");
		
		m_buffer.resize(2 * m_main_block_mod);
		m_buffer_pos = 0;
	}
	~this() {}
protected:
	/**
	* The block processor, implemented by subclasses
	* @param input some input bytes
	* @param length the size of input, guaranteed to be a multiple
	*		  of block_size
	*/
	abstract void buffered_block(in ubyte* input, size_t length);

	/**
	* The final block, implemented by subclasses
	* @param input some input bytes
	* @param length the size of input, guaranteed to be at least
	*		  final_minimum bytes
	*/
	abstract void buffered_final(in ubyte* input, size_t length);

	/**
	* @return block size of inputs
	*/
	final size_t buffered_block_size() const { return m_main_block_mod; }

	/**
	* @return current position in the buffer
	*/
	final size_t current_position() const { return m_buffer_pos; }

	/**
	* Reset the buffer position
	*/
	final void buffer_reset() { m_buffer_pos = 0; }
private:
	size_t m_main_block_mod, m_final_minimum;

	Secure_Vector!ubyte m_buffer;
	size_t m_buffer_pos;
}