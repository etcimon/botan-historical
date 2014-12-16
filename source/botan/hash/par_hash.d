/*
* Parallel Hash
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.par_hash;

import botan.constants;
static if (BOTAN_HAS_PARALLEL_HASH):

import botan.hash.hash;
import botan.utils.types;
import botan.utils.parsing;

/**
* Parallel Hashes
*/
class Parallel : HashFunction
{
public:
    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        foreach (hash; m_hashes)
            hash.clear();
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        Vector!string names;
        
        foreach (hash; m_hashes)
            names.pushBack(hash.name);
        
        return "Parallel(" ~ stringJoin(names, ',') ~ ")";
    }

    /*
    * Return a clone of this object
    */
    override HashFunction clone() const
    {
        Vector!HashFunction hash_copies;
        
        foreach (hash; m_hashes)
            hash_copies.pushBack(hash.clone());
        
        return new Parallel(hash_copies);
    }

    /*
    * Return output size
    */
    override @property size_t outputLength() const
    {
        size_t sum = 0;
        
        foreach (hash; m_hashes)
            sum += hash.outputLength;
        return sum;
    }

    /**
    * Constructor
    * @param hash_input = a set of hashes to compute in parallel
    */
    this(Vector!HashFunction hash_input)
    {
        m_hashes = hash_input;
    }

    /*
    * Parallel Destructor
    */
    ~this()
    {
        foreach (hash; m_hashes)
            delete hash;
    }
protected:
    /*
    * Update the hash
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        foreach (hash; m_hashes)
            hash.update(input, length);
    }

    /*
    * Finalize the hash
    */
    override void finalResult(ubyte* output)
    {
        uint offset = 0;
        
        foreach (hash; m_hashes)
        {
            hash.flushInto(output + offset);
            offset += hash.outputLength;
        }
    }

    Vector!HashFunction m_hashes;
}