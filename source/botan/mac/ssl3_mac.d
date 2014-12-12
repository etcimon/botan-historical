/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.ssl3_mac;

import botan.constants;
static if (BOTAN_HAS_SSL3_MAC):

import botan.hash.hash;
import botan.mac.mac;
/**
* A MAC only used in SSLv3. Do not use elsewhere! Use HMAC instead.
*/
final class SSL3MAC : MessageAuthenticationCode, SymmetricAlgorithm
{
public:
    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "SSL3-MAC(" ~ m_hash.name ~ ")";
    }

    override @property size_t outputLength() const { return m_hash.outputLength; }

    /*
    * Return a clone of this object
    */
    override MessageAuthenticationCode clone() const
    {
        return new SSL3MAC(m_hash.clone());
    }


    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_hash.clear();
        zap(m_ikey);
        zap(m_okey);
    }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(m_hash.outputLength);
    }

    /**
    * @param hash = the underlying hash to use
    */
    this(HashFunction hash)
    {
        m_hash = hash;
        if (m_hash.hashBlockSize == 0)
            throw new InvalidArgument("SSL3-MAC cannot be used with " ~ m_hash.name);
    }
protected:
    /*
    * Update a SSL3-MAC Calculation
    */
    override void addData(in ubyte* input, size_t length)
    {
        m_hash.update(input, length);
    }

    /*
    * Finalize a SSL3-MAC Calculation
    */
    override void finalResult(ubyte* mac)
    {
        m_hash.flushInto(mac);
        m_hash.update(m_okey);
        m_hash.update(mac, outputLength());
        m_hash.flushInto(mac);
        m_hash.update(m_ikey);
    }

    /*
    * SSL3-MAC Key Schedule
    */
    override void keySchedule(in ubyte* key, size_t length)
    {
        m_hash.clear();
        
        // Quirk to deal with specification bug
        const size_t inner_hash_length = (m_hash.name == "SHA-160") ? 60 : m_hash.hashBlockSize;
        
        m_ikey.reserve(inner_hash_length);
        m_okey.reserve(inner_hash_length);
        
        std.algorithm.fill(m_ikey.ptr, m_ikey.end(), 0x36);
        std.algorithm.fill(m_okey.ptr, m_okey.end(), 0x5C);
        
        copyMem(m_ikey.ptr, key, length);
        copyMem(m_okey.ptr, key, length);
        
        m_hash.update(m_ikey);
    }

    Unique!HashFunction m_hash;
    SecureVector!ubyte m_ikey, m_okey;
}