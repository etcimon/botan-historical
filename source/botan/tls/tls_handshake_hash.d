/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_handshake_hash;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.utils.memory.zeroize;
import botan.tls.tls_version;
import botan.tls.tls_magic;
import botan.tls.tls_exceptn;
import botan.hash.hash;
import botan.libstate.libstate;
import botan.tls.tls_exceptn;
import botan.libstate.libstate;
import botan.hash.hash;
import botan.utils.types;

/**
* TLS Handshake Hash
*/
class Handshake_Hash
{
public:
    void update(in ubyte* input, size_t length)
    { m_data ~= input[0 .. length]; }

    void update(in Vector!ubyte input)
    { m_data ~= input; }

    /**
    * Return a TLS Handshake Hash
    */
    Secure_Vector!ubyte flushInto(TLS_Protocol_Version _version, in string mac_algo) const
    {
        Algorithm_Factory af = global_state().algorithm_factory();
        
        Unique!HashFunction hash;
        
        if (_version.supports_ciphersuite_specific_prf())
        {
            if (mac_algo == "MD5" || mac_algo == "SHA-1")
                hash = af.make_hash_function("SHA-256");
            else
                hash = af.make_hash_function(mac_algo);
        }
        else
            hash = af.make_hash_function("Parallel(MD5,SHA-160)");
        
        hash.update(m_data);
        return hash.finished();
    }

    /**
    * Return a SSLv3 Handshake Hash
    */
    Secure_Vector!ubyte final_ssl3(in Secure_Vector!ubyte secret) const
    {
        const ubyte PAD_INNER = 0x36, PAD_OUTER = 0x5C;
        
        Algorithm_Factory af = global_state().algorithm_factory();
        
        Unique!HashFunction md5 = af.make_hash_function("MD5");
        Unique!HashFunction sha1 = af.make_hash_function("SHA-1");
        
        md5.update(m_data);
        sha1.update(m_data);
        
        md5.update(secret);
        sha1.update(secret);
        
        foreach (size_t i; 0 .. 48)
            md5.update(PAD_INNER);
        foreach (size_t i; 0 .. 40)
            sha1.update(PAD_INNER);
        
        Secure_Vector!ubyte inner_md5 = md5.finished(), inner_sha1 = sha1.finished();
        
        md5.update(secret);
        sha1.update(secret);
        
        foreach (size_t i; 0 .. 48)
            md5.update(PAD_OUTER);
        foreach (size_t i; 0 .. 40)
            sha1.update(PAD_OUTER);
        
        md5.update(inner_md5);
        sha1.update(inner_sha1);
        
        Secure_Vector!ubyte output;
        output ~= md5.finished();
        output ~= sha1.finished();
        return output;
    }

    const Vector!ubyte get_contents() const
    { return m_data; }

    void reset() { m_data.clear(); }
private:
    Vector!ubyte m_data;
}