/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.buf_filt;

import botan.alloc.secmem;

import botan.utils.mem_ops;
import botan.utils.rounding;
import stdexcept;

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
		
		if (buffer_pos + input_size >= main_block_mod + final_minimum)
		{
			size_t to_copy = std.algorithm.min(buffer.length - buffer_pos, input_size);
			
			copy_mem(&buffer[buffer_pos], input, to_copy);
			buffer_pos += to_copy;
			
			input += to_copy;
			input_size -= to_copy;
			
			size_t total_to_consume =
				round_down(std.algorithm.min(buffer_pos,
				                             buffer_pos + input_size - final_minimum),
				           main_block_mod);
			
			buffered_block(&buffer[0], total_to_consume);
			
			buffer_pos -= total_to_consume;
			
			copy_mem(&buffer[0], &buffer[0] + total_to_consume, buffer_pos);
		}
		
		if (input_size >= final_minimum)
		{
			size_t full_blocks = (input_size - final_minimum) / main_block_mod;
			size_t to_copy = full_blocks * main_block_mod;
			
			if (to_copy)
			{
				buffered_block(input, to_copy);
				
				input += to_copy;
				input_size -= to_copy;
			}
		}
		
		copy_mem(&buffer[buffer_pos], input, input_size);
		buffer_pos += input_size;
	}

	void write(in Vector!( ubyte, Alloc ) input)
	{
		write(&input[0], input.length);
	}

	/**
	* Finish a message, emitting to buffered_block and buffered_final
	* Will throw new an exception if less than final_minimum bytes were
	* written into the filter.
	*/
	void end_msg()
	{
		if (buffer_pos < final_minimum)
			throw new Exception("Buffered filter end_msg without enough input");
		
		size_t spare_blocks = (buffer_pos - final_minimum) / main_block_mod;
		
		if (spare_blocks)
		{
			size_t spare_bytes = main_block_mod * spare_blocks;
			buffered_block(&buffer[0], spare_bytes);
			buffered_final(&buffer[spare_bytes], buffer_pos - spare_bytes);
		}
		else
		{
			buffered_final(&buffer[0], buffer_pos);
		}
		
		buffer_pos = 0;
	}

	/**
	* Initialize a Buffered_Filter
	* @param _block_size the function buffered_block will be called
	*		  with inputs which are a multiple of this size
	* @param _final_minimum the function buffered_final will be called
	*		  with at least this many bytes.
	*/
	this(size_t _block_size, size_t _final_minimum)
	{
		
		main_block_mod = _block_size;
		final_minimum = _final_minimum;
		
		if (main_block_mod == 0)
			throw new Invalid_Argument("main_block_mod == 0");
		
		if (final_minimum > main_block_mod)
			throw new Invalid_Argument("final_minimum > main_block_mod");
		
		buffer.resize(2 * main_block_mod);
		buffer_pos = 0;
	}
	~this() {}
package:
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
	size_t buffered_block_size() const { return main_block_mod; }

	/**
	* @return current position in the buffer
	*/
	size_t current_position() const { return buffer_pos; }

	/**
	* Reset the buffer position
	*/
	void buffer_reset() { buffer_pos = 0; }
private:
	size_t main_block_mod, final_minimum;

	SafeVector!ubyte buffer;
	size_t buffer_pos;
};