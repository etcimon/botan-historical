/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.kdf2;
import botan.kdf.kdf;
import botan.hash.hash;
import botan.utils.types;

/**
* KDF2, from IEEE 1363
*/
class KDF2 : KDF
{
public:
    /*
    * KDF2 Key Derivation Mechanism
    */
    override SecureVector!ubyte derive(size_t out_len,
                               const(ubyte)* secret, 
                               size_t secret_len,
                               const(ubyte)* P, 
                               size_t P_len) const
    {
        HashFunction hash = cast(HashFunction)*m_hash;
        SecureVector!ubyte output;
        uint counter = 1;
        
        while (out_len && counter)
        {
            hash.update(secret, secret_len);
            hash.updateBigEndian(counter);
            hash.update(P, P_len);
            
            SecureVector!ubyte hash_result = hash.finished();
            
            size_t added = std.algorithm.min(hash_result.length, out_len);
            output ~= hash_result.ptr[0 .. added];
            out_len -= added;
            
            ++counter;
        }
        
        return output;
    }

    override @property string name() const { return "KDF2(" ~ m_hash.name ~ ")"; }
    override KDF clone() const { return new KDF2(m_hash.clone()); }

    this(HashFunction h) { m_hash = h; }
private:
    Unique!HashFunction m_hash;
}
