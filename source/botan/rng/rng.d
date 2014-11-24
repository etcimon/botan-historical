/*
* RandomNumberGenerator
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.rng.rng;

import botan.entropy.entropy_src;
import botan.utils.exceptn;
// import string;
import core.sync.mutex;
import botan.rng.hmac_rng;
import botan.libstate.libstate;
import botan.utils.types : Unique;

/**
* This class represents a random number (RNG) generator object.
*/
class RandomNumberGenerator
{
public:
    /**
    * Create a seeded and active RNG object for general application use
    * Added in 1.8.0
    */
    static RandomNumberGenerator make_rng()
    {
        return make_rng(global_state().algorithm_factory());
    }

    /**
    * Create a seeded and active RNG object for general application use
    * Added in 1.11.5
    */
    static RandomNumberGenerator make_rng(Algorithm_Factory af)
    {
        RandomNumberGenerator rng = new HMAC_RNG(af.make_mac("HMAC(SHA-512)"),
                                                 af.make_mac("HMAC(SHA-256)"));
        
        rng.reseed(256);
        
        return rng;
    }
    /**
    * Randomize a ubyte array.
    * @param output the ubyte array to hold the random output.
    * @param length the length of the ubyte array output.
    */
    abstract void randomize(ubyte* output, size_t length);

    /**
    * Return a random vector
    * @param bytes number of bytes in the result
    * @return randomized vector of length bytes
    */
    abstract Secure_Vector!ubyte random_vec(size_t bytes)
    {
        Secure_Vector!ubyte output = Secure_Vector!ubyte(bytes);
        randomize(output.ptr, output.length);
        return output;
    }

    /**
    * Return a random ubyte
    * @return random ubyte
    */
    final ubyte next_byte()
    {
        ubyte output;
        this.randomize(&output, 1);
        return output;
    }

    /**
    * Check whether this RNG is seeded.
    * @return true if this RNG was already seeded, false otherwise.
    */
    abstract bool is_seeded() const;

    /**
    * Clear all internally held values of this RNG.
    */
    abstract void clear();

    /**
    * Return the name of this object
    */
    abstract @property string name() const;

    /**
    * Seed this RNG using the entropy sources it contains.
    * @param bits_to_collect is the number of bits of entropy to
                attempt to gather from the entropy sources
    */
    abstract void reseed(size_t bits_to_collect);

    /**
    * Add entropy to this RNG.
    * @param input a ubyte array containg the entropy to be added
    * @param length the length of the ubyte array in
    */
    abstract void add_entropy(in ubyte* input, size_t length);

    this() {}
    ~this() {}
}

/**
* Null/stub RNG - fails if you try to use it for anything
*/
class Null_RNG : RandomNumberGenerator
{
public:
    override void randomize(ubyte*, size_t) { throw new PRNG_Unseeded("Null_RNG"); }

    override void clear() {}

    override @property string name() const { return "Null_RNG"; }

    override void reseed(size_t) {}
    override bool is_seeded() const { return false; }
    override void add_entropy(const ubyte[], size_t) {}
}

/**
* Wraps access to a RNG in a mutex
*/
shared class Serialized_RNG : RandomNumberGenerator
{
public:
    synchronized void randomize(ubyte* output, size_t length)
    {
        m_rng.randomize(output, len);
    }

    synchronized bool is_seeded() const
    {
        return m_rng.is_seeded();
    }

    synchronized void clear()
    {
        m_rng.clear();
    }

    synchronized @property string name() const
    {
        return m_rng.name;
    }

    synchronized void reseed(size_t poll_bits)
    {
        m_rng.reseed(poll_bits);
    }

    synchronized void add_entropy(in ubyte* input, size_t len)
    {
        m_rng.add_entropy(input, len);
    }

    this()
    {
        m_rng = RandomNumberGenerator.make_rng();
    }

private:
    Unique!RandomNumberGenerator m_rng;
}
