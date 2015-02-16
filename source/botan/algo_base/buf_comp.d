/*
* Buffered Computation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.algo_base.buf_comp;

import memutils.vector;
import botan.utils.get_byte;
import botan.utils.types;

/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
interface BufferedComputation
{
public:

    /**
    * Add new input to process.
    * @param input = the input to process as a ubyte array
    */
    final void update(in ubyte[] input) { addData(input.ptr, input.length); }

    /**
    * Add new input to process.
    * @param input = the input to process as a ubyte array
    * @param length = of param in in bytes
    */
    final void update(const(ubyte)* input, size_t length) { addData(input, length); }

    /**
    * Add new input to process.
    * @param input = the input to process as a SecureVector
    */
    final void update(T, ALLOC)(auto const ref RefCounted!(Vector!(T, ALLOC)) input)
    {
        addData(input.ptr, input.length);
    }

    /**
    * Add new input to process.
    * @param input = the input to process as a Vector
    */
    final void update(T, ALLOC)(auto const ref Vector!(T, ALLOC) input)
    {
        addData(input.ptr, input.length);
    }

    /**
    * Add an integer in big-endian order
    * @param input = the value
    */
    final void updateBigEndian(T)(in T input)
    {
        foreach (size_t i; 0 .. T.sizeof)
        {
            ubyte b = get_byte(i, input);
            addData(&b, 1);
        }
    }

    /**
    * Add new input to process.
    * @param str = the input to process as a string. Will be interpreted
    * as a ubyte array based on
    * the strings encoding.
    */
    final void update(in string str)
    {
        addData(str.ptr, str.length);
    }

    /**
    * Process a single ubyte.
    * @param input = the ubyte to process
    */
    final void update(ubyte input) { addData(&input, 1); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @param output = The ubyte array to be filled with the result.
    * Must be of length outputLength()
    */
    final void flushInto(ref ubyte[] output) 
    in { assert(output.length == outputLength); }
    body { finalResult(output.ptr); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @param output = The ubyte array to be filled with the result.
    * Must be of length outputLength()
    */
    final void flushInto(ubyte* output) { finalResult(output); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * @return SecureVector holding the result
    */
    final SecureVector!ubyte finished()
    {
        SecureVector!ubyte output = SecureVector!ubyte(outputLength());
        finalResult(output.ptr);
        return output.move;
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and finished() consecutively.
    * @param input = the input to process as a ubyte array
    * @param length = the length of the ubyte array
    * @result the result of the call to finished()
    */
    final SecureVector!ubyte process(in ubyte[] input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and finished() consecutively.
    * @param input = the input to process as a ubyte array
    * @param length = the length of the ubyte array
    * @result the result of the call to finished()
    */
    final SecureVector!ubyte process(const(ubyte)* input, size_t length)
    {
        addData(input, length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and finished() consecutively.
    * @param input = the input to process
    * @result the result of the call to finished()
    */
    final SecureVector!ubyte process(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and finished() consecutively.
    * @param input = the input to process
    * @result the result of the call to finished()
    */
    final SecureVector!ubyte process(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling update()
    * and finished() consecutively.
    * @param input = the input to process as a string
    * @result the result of the call to finished()
    */
    final SecureVector!ubyte process(in string input)
    {
        update(input);
        return finished();
    }

    final void addData(T)(in T input, size_t length) {
        addData(cast(const(ubyte)*)input, length);
    }

    /**
    * @return length of the output of this function in bytes
    */
    abstract @property size_t outputLength() const;

protected:
    /**
    * Add more data to the computation
    * @param input = is an input buffer
    * @param length = is the length of input in bytes
    */
    abstract void addData(const(ubyte)* input, size_t length);

    /**
    * Write the final output to out
    * @param output = is an output buffer of outputLength()
    */
    abstract void finalResult(ubyte* output);
}