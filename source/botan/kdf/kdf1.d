/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.kdf1;

import botan.kdf.kdf;
import botan.hash.hash;
import botan.utils.types;

/**
* KDF1, from IEEE 1363
*/
class KDF1 : KDF
{
public:
    /*
    * KDF1 Key Derivation Mechanism
    */
    override SecureVector!ubyte derive(size_t,
                            in ubyte* secret, size_t secret_len,
                            in ubyte* P, size_t P_len) const
    {
        m_hash.update(secret, secret_len);
        m_hash.update(P, P_len);
        return m_hash.finished();
    }


    override @property string name() const { return "KDF1(" ~ m_hash.name ~ ")"; }
    override KDF clone() const { return new KDF1(m_hash.clone()); }

    this(HashFunction h) 
    {
        m_hash = h;
    }
private:
    Unique!HashFunction m_hash;
}

