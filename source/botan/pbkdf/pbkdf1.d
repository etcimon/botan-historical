/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbkdf.pbkdf1;

import botan.constants;
static if (BOTAN_HAS_PBKDF1):

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import std.datetime;
import botan.utils.exceptn;

/**
* PKCS #5 v1 PBKDF, aka PBKDF1
* Can only generate a key up to the size of the hash output.
* Unless needed for backwards compatability, use PKCS5_PBKDF2
*/
final class PKCS5PBKDF1 : PBKDF
{
public:
    /**
    * Create a PKCS #5 instance using the specified hash function.
    * @param hash_in = pointer to a hash function object to use
    */
    this(HashFunction hash_input)
    {
        m_hash = hash_input;
    }

    @property string name() const
    {
        return "PBKDF1(" ~ m_hash.name ~ ")";
    }

    PBKDF clone() const
    {
        return new PKCS5PBKDF1(m_hash.clone());
    }

    /*
    * Return a PKCS#5 PBKDF1 derived key
    */
    Pair!(size_t, OctetString) keyDerivation(size_t key_len,
                                              in string passphrase,
                                              in ubyte* salt, size_t salt_len,
                                              size_t iterations,
                                              Duration loop_for) const
    {
        if (key_len > m_hash.output_length)
            throw new InvalidArgument("PKCS5_PBKDF1: Requested output length too long");
        
        m_hash.update(passphrase);
        m_hash.update(salt, salt_len);
        SecureVector!ubyte key = m_hash.finished();
        
        const start = Clock.currTime();
        size_t iterations_performed = 1;
        
        while (true)
        {
            if (iterations == 0)
            {
                if (iterations_performed % 10000 == 0)
                {
                    auto time_taken = Clock.currTime() - start;
                    if (time_taken > loop_for)
                        break;
                }
            }
            else if (iterations_performed == iterations)
                break;
            
            m_hash.update(key);
            m_hash.flushInto(key.ptr);
            
            ++iterations_performed;
        }
        
        return Pair(iterations_performed,
                    OctetString(key.ptr, std.algorithm.min(key_len, key.length)));
    }
private:
    Unique!HashFunction m_hash;
}

