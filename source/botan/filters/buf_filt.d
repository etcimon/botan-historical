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
class BufferedFilter
{
public:
    /**
    * Write bytes into the buffered filter, which will them emit them
    * in calls to bufferedBlock in the subclass
    * @param input = the input bytes
    * @param input_size = of input in bytes
    */
    void write(in ubyte* input, size_t input_size)
    {
        if (!input_size)
            return;
        
        if (m_buffer_pos + input_size >= m_main_block_mod + m_final_minimum)
        {
            size_t to_copy = std.algorithm.min(m_buffer.length - m_buffer_pos, input_size);
            
            copyMem(&m_buffer[m_buffer_pos], input, to_copy);
            m_buffer_pos += to_copy;
            
            input += to_copy;
            input_size -= to_copy;
            
            size_t total_to_consume = roundDown(std.algorithm.min(m_buffer_pos,
                                                 m_buffer_pos + input_size - m_final_minimum),
                                                 m_main_block_mod);
            
            bufferedBlock(m_buffer.ptr, total_to_consume);
            
            m_buffer_pos -= total_to_consume;
            
            copyMem(m_buffer.ptr, m_buffer.ptr + total_to_consume, buffer_pos);
        }
        
        if (input_size >= m_final_minimum)
        {
            size_t full_blocks = (input_size - m_final_minimum) / m_main_block_mod;
            size_t to_copy = full_blocks * m_main_block_mod;
            
            if (to_copy)
            {
                bufferedBlock(input, to_copy);
                
                input += to_copy;
                input_size -= to_copy;
            }
        }
        
        copyMem(&m_buffer[buffer_pos], input, input_size);
        m_buffer_pos += input_size;
    }

    void write(Alloc)(in Vector!( ubyte, Alloc ) input)
    {
        write(input.ptr, input.length);
    }

    /**
    * Finish a message, emitting to bufferedBlock and bufferedFinal
    * Will throw new an exception if less than final_minimum bytes were
    * written into the filter.
    */
    void endMsg()
    {
        if (m_buffer_pos < m_final_minimum)
            throw new Exception("Buffered filter endMsg without enough input");
        
        size_t spare_blocks = (m_buffer_pos - m_final_minimum) / m_main_block_mod;
        
        if (spare_blocks)
        {
            size_t spare_bytes = m_main_block_mod * spare_blocks;
            bufferedBlock(m_buffer.ptr, spare_bytes);
            bufferedFinal(&m_buffer[spare_bytes], m_buffer_pos - spare_bytes);
        }
        else
        {
            bufferedFinal(m_buffer.ptr, m_buffer_pos);
        }
        
        m_buffer_pos = 0;
    }

    /**
    * Initialize a BufferedFilter
    * @param block_size = the function bufferedBlock will be called
    *          with inputs which are a multiple of this size
    * @param final_minimum = the function bufferedFinal will be called
    *          with at least this many bytes.
    */
    this(size_t block_size, size_t final_minimum)
    {
        
        m_main_block_mod = block_size;
        m_final_minimum = final_minimum;
        
        if (m_main_block_mod == 0)
            throw new InvalidArgument("main_block_mod == 0");
        
        if (m_final_minimum > m_main_block_mod)
            throw new InvalidArgument("final_minimum > main_block_mod");
        
        m_buffer.resize(2 * m_main_block_mod);
        m_buffer_pos = 0;
    }
    ~this() {}
protected:
    /**
    * The block processor, implemented by subclasses
    * @param input = some input bytes
    * @param length = the size of input, guaranteed to be a multiple
    *          of block_size
    */
    abstract void bufferedBlock(in ubyte* input, size_t length);

    /**
    * The final block, implemented by subclasses
    * @param input = some input bytes
    * @param length = the size of input, guaranteed to be at least
    *          final_minimum bytes
    */
    abstract void bufferedFinal(in ubyte* input, size_t length);

    /**
    * @return block size of inputs
    */
    final size_t bufferedBlockSize() const { return m_main_block_mod; }

    /**
    * @return current position in the buffer
    */
    final size_t currentPosition() const { return m_buffer_pos; }

    /**
    * Reset the buffer position
    */
    final void bufferReset() { m_buffer_pos = 0; }
private:
    size_t m_main_block_mod, m_final_minimum;

    SecureVector!ubyte m_buffer;
    size_t m_buffer_pos;
}