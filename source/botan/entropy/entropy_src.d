/*
* EntropySource
* (C) 2008-2009,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.entropy_src;

import botan.utils.memory.zeroize;
import botan.utils.types;

/**
* Class used to accumulate the poll results of EntropySources
*/
struct Entropy_Accumulator
{
public:
    /**
    * Initialize an Entropy_Accumulator
    * @param goal = is how many bits we would like to collect
    */
    this(bool delegate(in ubyte*, size_t len, double) accum)
    {
        m_accum_fn = accum; 
        m_done = false;
    }

    ~this() {}

    /**
    * Get a cached I/O buffer (purely for minimizing allocation
    * overhead to polls)
    *
    * @param size = requested size for the I/O buffer
    * @return cached I/O buffer for repeated polls
    */
    Secure_Vector!ubyte get_io_buffer(size_t size)
    {
        m_io_buffer.clear();
        m_io_buffer.resize(size);
        return m_io_buffer;
    }

    /**
    * @return if our polling goal has been achieved
    */
    bool polling_goal_achieved() const { return m_done; }

    /**
    * Add entropy to the accumulator
    * @param bytes = the input bytes
    * @param length = specifies how many bytes the input is
    * @param entropy_bits_per_byte = is a best guess at how much
    * entropy per ubyte is in this input
    */
    void add(const void* bytes, size_t length, double entropy_bits_per_byte)
    {
        m_done = m_accum_fn(cast(const ubyte*)(bytes),
                                  length, entropy_bits_per_byte * length);
    }

    /**
    * Add entropy to the accumulator
    * @param v = is some value
    * @param entropy_bits_per_byte = is a best guess at how much
    * entropy per ubyte is in this input
    */
    void add(T)(in T v, double entropy_bits_per_byte)
    {
        add(&v, T.sizeof, entropy_bits_per_byte);
    }
private:
    bool delegate(in ubyte*, size_t, double) m_accum_fn;
    bool m_done;
    Secure_Vector!ubyte m_io_buffer;
}

/**
* Abstract interface to a source of entropy
*/
interface EntropySource
{
public:
    /**
    * @return name identifying this entropy source
    */
    @property string name() const;

    /**
    * Perform an entropy gathering poll
    * @param accum = is an accumulator object that will be given entropy
    */
    void poll(ref Entropy_Accumulator accum);
}