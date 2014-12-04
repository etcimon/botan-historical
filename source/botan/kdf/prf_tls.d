/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.prf_tls;
import botan.kdf.kdf;
import botan.mac.mac;
import botan.utils.xorBuf;
import botan.mac.hmac;
import botan.hash.md5;
import botan.hash.sha160;

/**
* PRF used in TLS 1.0/1.1
*/
class TLSPRF : KDF
{
public:
    /*
    * TLS PRF
    */
    SecureVector!ubyte derive(size_t key_len,
                            in ubyte* secret, size_t secret_len,
                            in ubyte* seed, size_t seed_len) const
    {
        SecureVector!ubyte output = SecureVector!ubyte(key_len);
        
        size_t S1_len = (secret_len + 1) / 2;
        size_t S2_len = (secret_len + 1) / 2;
        const ubyte* S1 = secret;
        const ubyte* S2 = secret + (secret_len - S2_len);
        
        P_hash(output, *m_hmac_md5,  S1, S1_len, seed, seed_len);
        P_hash(output, *m_hmac_sha1, S2, S2_len, seed, seed_len);
        
        return output;
    }

    @property string name() const { return "TLS-PRF"; }
    KDF clone() const { return new TLSPRF; }

    /*
    * TLS PRF Constructor and Destructor
    */
    this()
    {
        m_hmac_md5 = new HMAC(new MD5);
        m_hmac_sha1= new HMAC(new SHA160);
    }

private:
    Unique!MessageAuthenticationCode m_hmac_md5;
    Unique!MessageAuthenticationCode m_hmac_sha1;
}

/**
* PRF used in TLS 1.2
*/
class TLS12PRF : KDF
{
public:
    SecureVector!ubyte derive(size_t key_len,
                                   in ubyte* secret, size_t secret_len,
                                   in ubyte* seed, size_t seed_len) const
    {
        SecureVector!ubyte output = SecureVector!ubyte(key_len);
        
        P_hash(output, *m_hmac, secret, secret_len, seed, seed_len);
        
        return output;
    }

    @property string name() const { return "TLSv12-PRF(" ~ m_hmac.name ~ ")"; }
    KDF clone() const { return new TLS12PRF(m_hmac.clone()); }

    /*
    * TLS v1.2 PRF Constructor and Destructor
    */
    this(MessageAuthenticationCode mac)
    {
        m_hmac = mac;
    }
private:
    Unique!MessageAuthenticationCode m_hmac;
}


private:
/*
* TLS PRF P_hash function
*/
void pHash(SecureVector!ubyte output,
            MessageAuthenticationCode mac,
            in ubyte* secret, size_t secret_len,
            in ubyte* seed, size_t seed_len) pure
{
    try
    {
        mac.setKey(secret, secret_len);
    }
    catch(InvalidKeyLength)
    {
        throw new InternalError("The premaster secret of " ~ to!string(secret_len) ~ " bytes is too long for the PRF");
    }
    
    SecureVector!ubyte A = SecureVector!ubyte(seed, seed + seed_len);
    
    size_t offset = 0;
    
    while (offset != output.length)
    {
        const size_t this_block_len = std.algorithm.min(mac.output_length, output.length - offset);
        
        A = mac.process(A);
        
        mac.update(A);
        mac.update(seed, seed_len);
        SecureVector!ubyte block = mac.finished();
        
        xorBuf(&output[offset], block.ptr, this_block_len);
        offset += this_block_len;
    }
}