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
class DLIES_Encryptor : PK_Encryptor
{
public:
    /*
    * DLIES_Encryptor Constructor
    */
    this(in PK_Key_Agreement_Key key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_keylen = 20)
    { 
        m_ka = PK_Key_Agreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_keylen;
        m_my_key = key.public_value();
    }

    /*
    * Set the other parties public key
    */
    void set_other_key(in Vector!ubyte ok)
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
            throw new Invalid_Argument("DLIES: Plaintext too large");
        if (m_other_key.empty)
            throw new Invalid_State("DLIES: The other key was never set");
        
        Secure_Vector!ubyte output = Secure_Vector!ubyte(m_my_key.length + length + m_mac.output_length);
        buffer_insert(output, 0, m_my_key);
        buffer_insert(output, m_my_key.length, input, length);
        
        Secure_Vector!ubyte vz = Secure_Vector!(m_my_key.ptr, m_my_key.end());
        vz ~= m_ka.derive_key(0, m_other_key).bits_of();
        
        const size_t K_LENGTH = length + m_mac_keylen;
        OctetString K = m_kdf.derive_key(K_LENGTH, vz);
        
        if (K.length != K_LENGTH)
            throw new Encoding_Error("DLIES: KDF did not provide sufficient output");
        ubyte* C = &output[m_my_key.length];
        
        xor_buf(C, K.ptr + m_mac_keylen, length);
        m_mac.set_key(K.ptr, m_mac_keylen);
        
        m_mac.update(C, length);
        foreach (size_t j; 0 .. 8)
            m_mac.update(0);
        
        m_mac.flushInto(C + length);
        
        return unlock(output);
    }

    /*
    * Return the max size, in bytes, of a message
    */
    size_t maximum_input_size() const
    {
        return 32;
    }

    Vector!ubyte m_other_key, m_my_key;

    PK_Key_Agreement m_ka;
    Unique!KDF m_kdf;
    Unique!MessageAuthenticationCode m_mac;
    size_t m_mac_keylen;
}

/**
* DLIES Decryption
*/
class DLIES_Decryptor : PK_Decryptor
{
public:
    /*
    * DLIES_Decryptor Constructor
    */
    this(in PK_Key_Agreement_Key key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_key_len = 20)
    {
        m_ka = PK_Key_Agreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_key_len;
        m_my_key = key.public_value();
    }

private:
    /*
    * DLIES Decryption
    */
    Secure_Vector!ubyte dec(in ubyte* msg, size_t length) const
    {
        if (length < m_my_key.length + m_mac.output_length)
            throw new Decoding_Error("DLIES decryption: ciphertext is too short");
        
        const size_t CIPHER_LEN = length - m_my_key.length - m_mac.output_length;
        
        Vector!ubyte v = Vector!ubyte(msg, msg + m_my_key.length);
        
        Secure_Vector!ubyte C = Secure_Vector!ubyte(msg + m_my_key.length, msg + m_my_key.length + CIPHER_LEN);
        
        Secure_Vector!ubyte T = Secure_Vector!ubyte(msg + m_my_key.length + CIPHER_LEN,
                           msg + m_my_key.length + CIPHER_LEN + m_mac.output_length);
        
        Secure_Vector!ubyte vz = Secure_Vector!ubyte(msg, msg + m_my_key.length);
        vz ~= m_ka.derive_key(0, v).bits_of();
        
        const size_t K_LENGTH = C.length + m_mac_keylen;
        OctetString K = m_kdf.derive_key(K_LENGTH, vz);
        if (K.length != K_LENGTH)
            throw new Encoding_Error("DLIES: KDF did not provide sufficient output");
        
        m_mac.set_key(K.ptr, m_mac_keylen);
        m_mac.update(C);
        foreach (size_t j; 0 .. 8)
            m_mac.update(0);
        Secure_Vector!ubyte T2 = m_mac.flush();
        if (T != T2)
            throw new Decoding_Error("DLIES: message authentication failed");
        
        xor_buf(C, K.ptr + m_mac_keylen, C.length);
        
        return C;
    }

    Vector!ubyte m_my_key;

    PK_Key_Agreement m_ka;
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

size_t dlies_kat(string p,
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
    
    DL_Group domain = DL_Group(p_bn, g_bn);
    
    auto from = scoped!DH_PrivateKey(rng, domain, x1_bn);
    auto to = scoped!DH_PrivateKey(rng, domain, x2_bn);
    
    const string opt_str = "KDF2(SHA-1)/HMAC(SHA-1)/16";
    
    Vector!string options = split_on(opt_str, '/');
    
    if (options.length != 3)
        throw new Exception("DLIES needs three options: " ~ opt_str);
    
    const size_t mac_key_len = to!uint(options[2]);
    
    auto e = scoped!DLIES_Encryptor(from, get_kdf(options[0]), get_mac(options[1]), mac_key_len);
    
    auto d = scoped!DLIES_Decryptor(to, get_kdf(options[0]), get_mac(options[1]), mac_key_len);
    
    e.set_other_key(to.public_value());
    
    return validate_encryption(e, d, "DLIES", msg, "", ciphertext);
}

unittest
{
    size_t fails = 0;
    
    File dlies = File("test_data/pubkey/dlies.vec", "r");
    
    fails += run_tests_bb(dlies, "DLIES Encryption", "Ciphertext", true,
                          (string[string] m) {
                                return dlies_kat(m["P"], m["G"], m["X1"], m["X2"], m["Msg"], m["Ciphertext"]);
                            });
    
    test_report("dlies", total_tests, fails);
}