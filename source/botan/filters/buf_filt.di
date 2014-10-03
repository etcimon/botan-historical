/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.secmem;
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
		* @param in the input bytes
		* @param length of input in bytes
		*/
		void write(in byte* input, size_t length);

		void write(in Vector!( byte, Alloc ) input)
		{
			write(&input[0], input.size());
		}

		/**
		* Finish a message, emitting to buffered_block and buffered_final
		* Will throw new an exception if less than final_minimum bytes were
		* written into the filter.
		*/
		void end_msg();

		/**
		* Initialize a Buffered_Filter
		* @param block_size the function buffered_block will be called
		*		  with inputs which are a multiple of this size
		* @param final_minimum the function buffered_final will be called
		*		  with at least this many bytes.
		*/
		Buffered_Filter(size_t block_size, size_t final_minimum);

		~this() {}
	package:
		/**
		* The block processor, implemented by subclasses
		* @param input some input bytes
		* @param length the size of input, guaranteed to be a multiple
		*		  of block_size
		*/
		abstract void buffered_block(in byte* input, size_t length);

		/**
		* The final block, implemented by subclasses
		* @param input some input bytes
		* @param length the size of input, guaranteed to be at least
		*		  final_minimum bytes
		*/
		abstract void buffered_final(in byte* input, size_t length);

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

		SafeVector!byte buffer;
		size_t buffer_pos;
};