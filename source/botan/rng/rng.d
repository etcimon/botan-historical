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
    static RandomNumberGenerator makeRng()
    {
        return makeRng(globalState().algorithmFactory());
    }

    /**
    * Create a seeded and active RNG object for general application use
    * Added in 1.11.5
    */
    static RandomNumberGenerator makeRng(AlgorithmFactory af)
    {
        RandomNumberGenerator rng = new HMAC_RNG(af.makeMac("HMAC(SHA-512)"),
                                                 af.makeMac("HMAC(SHA-256)"));
        
        rng.reseed(256);
        
        return rng;
    }
    /**
    * Randomize a ubyte array.
    * @param output = the ubyte array to hold the random output.
    * @param length = the length of the ubyte array output.
    */
    abstract void randomize(ubyte* output, size_t length);

    /**
    * Return a random vector
    * @param bytes = number of bytes in the result
    * @return randomized vector of length bytes
    */
    abstract SecureVector!ubyte randomVec(size_t bytes)
    {
        SecureVector!ubyte output = SecureVector!ubyte(bytes);
        randomize(output.ptr, output.length);
        return output;
    }

    /**
    * Return a random ubyte
    * @return random ubyte
    */
    final ubyte nextByte()
    {
        ubyte output;
        this.randomize(&output, 1);
        return output;
    }

    /**
    * Check whether this RNG is seeded.
    * @return true if this RNG was already seeded, false otherwise.
    */
    abstract bool isSeeded() const;

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
    * @param bits_to_collect = is the number of bits of entropy to
                attempt to gather from the entropy sources
    */
    abstract void reseed(size_t bits_to_collect);

    /**
    * Add entropy to this RNG.
    * @param input = a ubyte array containg the entropy to be added
    * @param length = the length of the ubyte array in
    */
    abstract void addEntropy(in ubyte* input, size_t length);

    this() {}
    ~this() {}
}

/**
* Null/stub RNG - fails if you try to use it for anything
*/
class NullRNG : RandomNumberGenerator
{
public:
    override void randomize(ubyte*, size_t) { throw new PRNGUnseeded("Null_RNG"); }

    override void clear() {}

    override @property string name() const { return "Null_RNG"; }

    override void reseed(size_t) {}
    override bool isSeeded() const { return false; }
    override void addEntropy(const ubyte[], size_t) {}
}

/**
* Wraps access to a RNG in a mutex
*/
shared class SerializedRNG : RandomNumberGenerator
{
public:
    synchronized void randomize(ubyte* output, size_t length)
    {
        m_rng.randomize(output, len);
    }

    synchronized bool isSeeded() const
    {
        return m_rng.isSeeded();
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

    synchronized void addEntropy(in ubyte* input, size_t len)
    {
        m_rng.addEntropy(input, len);
    }

    this()
    {
        m_rng = RandomNumberGenerator.makeRng();
    }

private:
    Unique!RandomNumberGenerator m_rng;
}
