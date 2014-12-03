/*
* DLIES (Discrete Logarithm/Elliptic Curve Integrated Encryption Scheme): 
* Essentially the "DHAES" variant of ElGamal encryption.
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dlies;

import botan.constants;
static if (BOTAN_HAS_DLIES):

import botan.pubkey.pubkey;
import botan.mac.mac;
import botan.kdf.kdf;
import botan.utils.xor_buf;

/**
* DLIES Encryption
*/
class DLIESEncryptor : PK_Encryptor
{
public:
    /*
    * DLIES_Encryptor Constructor
    */
    this(in PKKeyAgreementKey key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_keylen = 20)
    { 
        m_ka = PKKeyAgreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_keylen;
        m_my_key = key.publicValue();
    }

    /*
    * Set the other parties public key
    */
    void setOtherKey(in Vector!ubyte ok)
    {
        m_other_key = ok;
    }
private:
    /*
    * DLIES Encryption
    */
    Vector!ubyte enc(in ubyte* input, size_t length,
                     RandomNumberGenerator) const
    {
        if (length > maximum_input_size())
            throw new InvalidArgument("DLIES: Plaintext too large");
        if (m_other_key.empty)
            throw new InvalidState("DLIES: The other key was never set");
        
        SecureVector!ubyte output = SecureVector!ubyte(m_my_key.length + length + m_mac.output_length);
        buffer_insert(output, 0, m_my_key);
        buffer_insert(output, m_my_key.length, input, length);
        
        SecureVector!ubyte vz = SecureVector!(m_my_key.ptr, m_my_key.end());
        vz ~= m_ka.deriveKey(0, m_other_key).bitsOf();
        
        const size_t K_LENGTH = length + m_mac_keylen;
        OctetString K = m_kdf.deriveKey(K_LENGTH, vz);
        
        if (K.length != K_LENGTH)
            throw new EncodingError("DLIES: KDF did not provide sufficient output");
        ubyte* C = &output[m_my_key.length];
        
        xor_buf(C, K.ptr + m_mac_keylen, length);
        m_mac.setKey(K.ptr, m_mac_keylen);
        
        m_mac.update(C, length);
        foreach (size_t j; 0 .. 8)
            m_mac.update(0);
        
        m_mac.flushInto(C + length);
        
        return unlock(output);
    }

    /*
    * Return the max size, in bytes, of a message
    */
    size_t maximumInputSize() const
    {
        return 32;
    }

    Vector!ubyte m_other_key, m_my_key;

    PKKeyAgreement m_ka;
    Unique!KDF m_kdf;
    Unique!MessageAuthenticationCode m_mac;
    size_t m_mac_keylen;
}

/**
* DLIES Decryption
*/
class DLIESDecryptor : PK_Decryptor
{
public:
    /*
    * DLIES_Decryptor Constructor
    */
    this(in PKKeyAgreementKey key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_key_len = 20)
    {
        m_ka = PKKeyAgreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_key_len;
        m_my_key = key.publicValue();
    }

private:
    /*
    * DLIES Decryption
    */
    SecureVector!ubyte dec(in ubyte* msg, size_t length) const
    {
        if (length < m_my_key.length + m_mac.output_length)
            throw new DecodingError("DLIES decryption: ciphertext is too short");
        
        const size_t CIPHER_LEN = length - m_my_key.length - m_mac.output_length;
        
        Vector!ubyte v = Vector!ubyte(msg, msg + m_my_key.length);
        
        SecureVector!ubyte C = SecureVector!ubyte(msg + m_my_key.length, msg + m_my_key.length + CIPHER_LEN);
        
        SecureVector!ubyte T = SecureVector!ubyte(msg + m_my_key.length + CIPHER_LEN,
                           msg + m_my_key.length + CIPHER_LEN + m_mac.output_length);
        
        SecureVector!ubyte vz = SecureVector!ubyte(msg, msg + m_my_key.length);
        vz ~= m_ka.deriveKey(0, v).bitsOf();
        
        const size_t K_LENGTH = C.length + m_mac_keylen;
        OctetString K = m_kdf.deriveKey(K_LENGTH, vz);
        if (K.length != K_LENGTH)
            throw new EncodingError("DLIES: KDF did not provide sufficient output");
        
        m_mac.setKey(K.ptr, m_mac_keylen);
        m_mac.update(C);
        foreach (size_t j; 0 .. 8)
            m_mac.update(0);
        SecureVector!ubyte T2 = m_mac.finished();
        if (T != T2)
            throw new DecodingError("DLIES: message authentication failed");
        
        xor_buf(C, K.ptr + m_mac_keylen, C.length);
        
        return C;
    }

    Vector!ubyte m_my_key;

    PKKeyAgreement m_ka;
    Unique!KDF m_kdf;
    Unique!MessageAuthenticationCode m_mac;
    size_t m_mac_keylen;
}


static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.codec.hex;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.libstate.lookup;
import botan.pubkey.algo.dh;
import core.atomic;

__gshared size_t total_tests;

size_t dliesKat(string p,
                 string g,
                 string x1,
                 string x2,
                 string msg,
                 string ciphertext)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    BigInt p_bn = BigInt(p);
    BigInt g_bn = BigInt(g);
    BigInt x1_bn = BigInt(x1);
    BigInt x2_bn = BigInt(x2);
    
    DLGroup domain = DLGroup(p_bn, g_bn);
    
    auto from = scoped!DHPrivateKey(rng, domain, x1_bn);
    auto to = scoped!DHPrivateKey(rng, domain, x2_bn);
    
    const string opt_str = "KDF2(SHA-1)/HMAC(SHA-1)/16";
    
    Vector!string options = split_on(opt_str, '/');
    
    if (options.length != 3)
        throw new Exception("DLIES needs three options: " ~ opt_str);
    
    const size_t mac_key_len = to!uint(options[2]);
    
    auto e = scoped!DLIES_Encryptor(from, get_kdf(options[0]), get_mac(options[1]), mac_key_len);
    
    auto d = scoped!DLIES_Decryptor(to, get_kdf(options[0]), get_mac(options[1]), mac_key_len);
    
    e.setOtherKey(to.publicValue());
    
    return validate_encryption(e, d, "DLIES", msg, "", ciphertext);
}

unittest
{
    size_t fails = 0;
    
    File dlies = File("test_data/pubkey/dlies.vec", "r");
    
    fails += runTestsBb(dlies, "DLIES Encryption", "Ciphertext", true,
                          (string[string] m) {
                                return dliesKat(m["P"], m["G"], m["X1"], m["X2"], m["Msg"], m["Ciphertext"]);
                            });
    
    testReport("dlies", total_tests, fails);
}