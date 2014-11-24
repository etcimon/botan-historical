/*
* Buffered Computation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.algo_base.buf_comp;

import botan.zeroize;
import botan.utils.get_byte;

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
    abstract @property size_t output_length() const;

    /**
    * Add new input to process.
    * @param input the input to process as a ubyte array
    */
    final void update(in ubyte[] input) { add_data(input.ptr, input.length); }

    /**
    * Add new input to process.
    * @param input the input to process as a ubyte array
    * @param length of param in in bytes
    */
    final void update(in ubyte* input, size_t length) { add_data(input, length); }

    /**
    * Add new input to process.
    * @param input the input to process as a Secure_Vector
    */
    final void update(in Secure_Vector!ubyte input)
    {
        add_data(input.ptr, input.length);
    }

    /**
    * Add new input to process.
    * @param input the input to process as a Vector
    */
    final void update(in Vector!ubyte input)
    {
        add_data(input.ptr, input.length);
    }

    /**
    * Add an integer in big-endian order
    * @param input the value
    */
    final void update_be(T)(in T input)
    {
        foreach (size_t i; 0 .. T.sizeof)
        {
            ubyte b = get_byte(i, input);
            add_data(&b, 1);
        }
    }

    /**
    * Add new input to process.
    * @param str the input to process as a string. Will be interpreted
    * as a ubyte array based on
    * the strings encoding.
    */
    final void update(in string str)
    {
        add_data(&str, str.length);
    }

    /**
    * Process a single ubyte.
    * @param input the ubyte to process
    */
    final void update(ubyte input) { add_data(&input, 1); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @param output The ubyte array to be filled with the result.
    * Must be of length output_length()
    */
    final void flushInto(ref ubyte[] output) 
    in { output.length == output_length; }
    body { final_result(output.ptr); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @param output The ubyte array to be filled with the result.
    * Must be of length output_length()
    */
    final void flushInto(ubyte* output) { final_result(output); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @return Secure_Vector holding the result
    */
    final Secure_Vector!ubyte flush()
    {
        Secure_Vector!ubyte output = Secure_Vector!ubyte(output_length());
        final_result(output.ptr);
        return output;
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and flush() consecutively.
    * @param input the input to process as a ubyte array
    * @param length the length of the ubyte array
    * @result the result of the call to flush()
    */
    final Secure_Vector!ubyte process(in ubyte[] input)
    {
        add_data(input);
        return flush();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and flush() consecutively.
    * @param input the input to process as a ubyte array
    * @param length the length of the ubyte array
    * @result the result of the call to flush()
    */
    final Secure_Vector!ubyte process(in ubyte* input, size_t length)
    {
        add_data(input, length);
        return flush();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and flush() consecutively.
    * @param input the input to process
    * @result the result of the call to flush()
    */
    final Secure_Vector!ubyte process(in Secure_Vector!ubyte input)
    {
        add_data(input[]);
        return flush();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and flush() consecutively.
    * @param input the input to process
    * @result the result of the call to flush()
    */
    final Secure_Vector!ubyte process(in Vector!ubyte input)
    {
        add_data(input[]);
        return flush();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and flush() consecutively.
    * @param input the input to process as a string
    * @result the result of the call to flush()
    */
    final Secure_Vector!ubyte process(in string input)
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
    abstract void add_data(in ubyte* input, size_t length);

    /**
    * Write the final output to out
    * @param output is an output buffer of output_length()
    */
    abstract void final_result(ubyte* output);
}