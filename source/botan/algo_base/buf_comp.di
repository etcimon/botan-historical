/*
* Buffered Computation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <botan/get_byte.h>
#include <string>
/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
class Buffered_Computation
{
	public:
		/**
		* @return length of the output of this function in bytes
		*/
		abstract size_t output_length() const = 0;

		/**
		* Add new input to process.
		* @param in the input to process as a byte array
		* @param length of param in in bytes
		*/
		void update(const byte[] input) { add_data(input, length); }

		/**
		* Add new input to process.
		* @param in the input to process as a secure_vector
		*/
		void update(in SafeArray!byte input)
		{
			add_data(&in[0], in.size());
		}

		/**
		* Add new input to process.
		* @param in the input to process as a std::vector
		*/
		void update(in Array!byte input)
		{
			add_data(&in[0], in.size());
		}

		/**
		* Add an integer in big-endian order
		* @param in the value
		*/
		template<typename T> void update_be(const T input)
		{
			for(size_t i = 0; i != sizeof(T); ++i)
			{
				byte b = get_byte(i, input);
				add_data(&b, 1);
			}
		}

		/**
		* Add new input to process.
		* @param str the input to process as a string. Will be interpreted
		* as a byte array based on
		* the strings encoding.
		*/
		void update(in string str)
		{
			add_data(cast(const byte*)(str.data()), str.size());
		}

		/**
		* Process a single byte.
		* @param in the byte to process
		*/
		void update(byte input) { add_data(&in, 1); }

		/**
		* Complete the computation and retrieve the
		* final result.
		* @param out The byte array to be filled with the result.
		* Must be of length output_length()
		*/
		void final(ref byte[] output) { final_result(out); }

		/**
		* Complete the computation and retrieve the
		* final result.
		* @return secure_vector holding the result
		*/
		SafeArray!byte final()
		{
			SafeArray!byte output(output_length());
			final_result(&output[0]);
			return output;
		}

		/**
		* Update and finalize computation. Does the same as calling update()
		* and final() consecutively.
		* @param in the input to process as a byte array
		* @param length the length of the byte array
		* @result the result of the call to final()
		*/
		SafeArray!byte process(const byte[] input)
		{
			add_data(input, length);
			return final();
		}

		/**
		* Update and finalize computation. Does the same as calling update()
		* and final() consecutively.
		* @param in the input to process
		* @result the result of the call to final()
		*/
		SafeArray!byte process(in SafeArray!byte input)
		{
			add_data(&in[0], in.size());
			return final();
		}

		/**
		* Update and finalize computation. Does the same as calling update()
		* and final() consecutively.
		* @param in the input to process
		* @result the result of the call to final()
		*/
		SafeArray!byte process(in Array!byte input)
		{
			add_data(&in[0], in.size());
			return final();
		}

		/**
		* Update and finalize computation. Does the same as calling update()
		* and final() consecutively.
		* @param in the input to process as a string
		* @result the result of the call to final()
		*/
		SafeArray!byte process(in string input)
		{
			update(input);
			return final();
		}

		abstract ~Buffered_Computation() {}
	private:
		/**
		* Add more data to the computation
		* @param input is an input buffer
		* @param length is the length of input in bytes
		*/
		abstract void add_data(const byte[] input, size_t length) = 0;

		/**
		* Write the final output to out
		* @param out is an output buffer of output_length()
		*/
		abstract void final_result(ref byte[] output) = 0;
};