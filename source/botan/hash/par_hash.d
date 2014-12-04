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
    void clear()
    {
        foreach (hash; m_hashes)
            hash.clear();
    }

    /*
    * Return the name of this type
    */
    @property string name() const
    {
        Vector!string names;
        
        foreach (hash; m_hashes)
            names.pushBack(hash.name);
        
        return "Parallel(" ~ stringJoin(names, ',') ~ ")";
    }

    /*
    * Return a clone of this object
    */
    HashFunction clone() const
    {
        Vector!HashFunction hash_copies;
        
        foreach (hash; m_hashes)
            hash_copies.pushBack(hash.clone());
        
        return new Parallel(hash_copies);
    }

    /*
    * Return output size
    */
    @property size_t outputLength() const
    {
        size_t sum = 0;
        
        foreach (hash; m_hashes)
            sum += hash.output_length;
        return sum;
    }

    /**
    * Constructor
    * @param hash_input = a set of hashes to compute in parallel
    */
    this(in Vector!HashFunction hash_input)
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
private:
    /*
    * Update the hash
    */
    void addData(in ubyte* input, size_t length)
    {
        foreach (hash; m_hashes)
            hash.update(input, length);
    }

    /*
    * Finalize the hash
    */
    void finalResult(ubyte* output)
    {
        uint offset = 0;
        
        foreach (hash; m_hashes)
        {
            hash.flushInto(output + offset);
            offset += hash.output_length;
        }
    }
    Vector!HashFunction m_hashes;
}