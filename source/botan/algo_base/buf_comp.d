/*
* Buffered Computation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.algo_base.buf_comp;

import botan.secmem;
import botan.get_byte;

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
	abstract size_t output_length() const;

	/**
	* Add new input to process.
	* @param in the input to process as a byte array
	* @param length of param in in bytes
	*/
	void update(in byte* input, size_t length) { add_data(input, length); }

	/**
	* Add new input to process.
	* @param in the input to process as a secure_vector
	*/
	void update(in SafeVector!byte input)
	{
		add_data(&input[0], input.size());
	}

	/**
	* Add new input to process.
	* @param in the input to process as a Vector
	*/
	void update(in Vector!byte input)
	{
		add_data(&input[0], input.size());
	}

	/**
	* Add an integer in big-endian order
	* @param in the value
	*/
	void update_be(T)(in T input)
	{
		for (size_t i = 0; i != sizeof(T); ++i)
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
		add_data(&str, str.length);
	}

	/**
	* Process a single byte.
	* @param in the byte to process
	*/
	void update(byte input) { add_data(&input, 1); }

	/**
	* Complete the computation and retrieve the
	* final result.
	* @param out The byte array to be filled with the result.
	* Must be of length output_length()
	*/
	void flushInto(byte* output) { final_result(output); }

	/**
	* Complete the computation and retrieve the
	* final result.
	* @return secure_vector holding the result
	*/
	SafeVector!byte flush()
	{
		SafeVector!byte output(output_length());
		final_result(&output[0]);
		return output;
	}

	/**
	* Update and finalize computation. Does the same as calling update()
	* and flush() consecutively.
	* @param in the input to process as a byte array
	* @param length the length of the byte array
	* @result the result of the call to flush()
	*/
	SafeVector!byte process(in byte* input, size_t length)
	{
		add_data(input, length);
		return flush();
	}

	/**
	* Update and finalize computation. Does the same as calling update()
	* and flush() consecutively.
	* @param in the input to process
	* @result the result of the call to flush()
	*/
	SafeVector!byte process(in SafeVector!byte input)
	{
		add_data(input[]);
		return flush();
	}

	/**
	* Update and finalize computation. Does the same as calling update()
	* and flush() consecutively.
	* @param in the input to process
	* @result the result of the call to flush()
	*/
	SafeVector!byte process(in Vector!byte input)
	{
		add_data(input[]);
		return flush();
	}

	/**
	* Update and finalize computation. Does the same as calling update()
	* and flush() consecutively.
	* @param in the input to process as a string
	* @result the result of the call to flush()
	*/
	SafeVector!byte process(in string input)
	{
		update(input);
		return flush();
	}

	~this() {}
private:
	/**
	* Add more data to the computation
	* @param input is an input buffer
	* @param length is the length of input in bytes
	*/
	abstract void add_data(in byte* input, size_t length);

	/**
	* Write the final output to out
	* @param out is an output buffer of output_length()
	*/
	abstract void final_result(byte* output);
}