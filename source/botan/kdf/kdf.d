/*
* Key Derivation Function interfaces
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.kdf;
import botan.utils.memory.zeroize;
import botan.utils.types;
// import string;
import botan.libstate.libstate;
import botan.algo_base.scan_name;
static if (BOTAN_HAS_KDF1)             import botan.kdf.kdf1;
static if (BOTAN_HAS_KDF2)             import botan.kdf.kdf2;
static if (BOTAN_HAS_X942_PRF)         import botan.kdf.prf_x942;
static if (BOTAN_HAS_SSL_V3_PRF)     import botan.prf_ssl3;
static if (BOTAN_HAS_TLS_V10_PRF)    import botan.kdf.prf_tls;

/**
* Key Derivation Function
*/
class KDF
{
public:
    ~this() {}

    abstract @property string name() const;

    /**
    * Derive a key
    * @param key_len = the desired output length in bytes
    * @param secret = the secret input
    * @param salt = a diversifier
    */
    Secure_Vector!ubyte derive_key(size_t key_len,
                                in Secure_Vector!ubyte secret,
                                in string salt = "") const
    {
        return derive_key(key_len, secret.ptr, secret.length,
                                cast(const ubyte*)(salt.ptr),
                                salt.length);
    }

    /**
    * Derive a key
    * @param key_len = the desired output length in bytes
    * @param secret = the secret input
    * @param salt = a diversifier
    */
    
    Secure_Vector!ubyte derive_key(Alloc, Alloc2)(size_t key_len,
                                                 in Vector!( ubyte, Alloc ) secret,
                                                 in Vector!( ubyte, Alloc2 ) salt) const
    {
        return derive_key(key_len,
                                secret.ptr, secret.length,
                                salt.ptr, salt.length);
    }

    /**
    * Derive a key
    * @param key_len = the desired output length in bytes
    * @param secret = the secret input
    * @param salt = a diversifier
    * @param salt_len = size of salt in bytes
    */
    Secure_Vector!ubyte derive_key(size_t key_len,
                                in Secure_Vector!ubyte secret,
                                in ubyte* salt,
                                size_t salt_len) const
    {
        return derive_key(key_len,
                            secret.ptr, secret.length,
                            salt, salt_len);
    }

    /**
    * Derive a key
    * @param key_len = the desired output length in bytes
    * @param secret = the secret input
    * @param secret_len = size of secret in bytes
    * @param salt = a diversifier
    */
    Secure_Vector!ubyte derive_key(size_t key_len,
                                in ubyte* secret,
                                size_t secret_len,
                                in string salt = "") const
    {
        return derive_key(key_len, secret, secret_len,
                                cast(const ubyte*)(salt.ptr),
                                salt.length);
    }

    /**
    * Derive a key
    * @param key_len = the desired output length in bytes
    * @param secret = the secret input
    * @param secret_len = size of secret in bytes
    * @param salt = a diversifier
    * @param salt_len = size of salt in bytes
    */
    Secure_Vector!ubyte derive_key(size_t key_len,
                                in ubyte* secret,
                                size_t secret_len,
                                in ubyte* salt,
                                size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len);
    }

    abstract KDF clone() const;
private:
    abstract Secure_Vector!ubyte
        derive(size_t key_len,
                 in ubyte* secret, size_t secret_len,
                 in ubyte* salt, size_t salt_len) const;
}

/**
* Factory method for KDF (key derivation function)
* @param algo_spec = the name of the KDF to create
* @return pointer to newly allocated object of that type
*/
KDF get_kdf(in string algo_spec)
{
    SCAN_Name request = SCAN_Name(algo_spec);
    
    Algorithm_Factory af = global_state().algorithm_factory();
    
    if (request.algo_name == "Raw")
        return null; // No KDF
    
    static if (BOTAN_HAS_KDF1) {
        if (request.algo_name == "KDF1" && request.arg_count() == 1)
            return new KDF1(af.make_hash_function(request.arg(0)));
    }
        
    static if (BOTAN_HAS_KDF2) {
        if (request.algo_name == "KDF2" && request.arg_count() == 1)
            return new KDF2(af.make_hash_function(request.arg(0)));
    }
        
    static if (BOTAN_HAS_X942_PRF) { 
        if (request.algo_name == "X9.42-PRF" && request.arg_count() == 1)
            return new X942_PRF(request.arg(0)); // OID
    }
        
    static if (BOTAN_HAS_SSL_V3_PRF) {
        if (request.algo_name == "SSL3-PRF" && request.arg_count() == 0)
            return new SSL3_PRF;
    }
        
    static if (BOTAN_HAS_TLS_V10_PRF) {
        if (request.algo_name == "TLS-PRF" && request.arg_count() == 0)
            return new TLS_PRF;
    }
        
    static if (BOTAN_HAS_TLS_V12_PRF) {
        if (request.algo_name == "TLS-12-PRF" && request.arg_count() == 1)
            return new TLS_12_PRF(af.make_mac("HMAC(" ~ request.arg(0) ~ ")"));
    }
    
    throw new Algorithm_Not_Found(algo_spec);
}

static if (BOTAN_TEST):

import botan.libstate.lookup;
import botan.codec.hex;

unittest
{
    auto test = (string input) {
        return run_tests(input, "KDF", "Output", true,
                         (string[string] vec)
                         {
            Unique!KDF kdf = get_kdf(vec["KDF"]);
            
            const size_t outlen = to!uint(vec["OutputLen"]);
            const auto salt = hex_decode(vec["Salt"]);
            const auto secret = hex_decode(vec["Secret"]);
            
            const auto key = kdf.derive_key(outlen, secret, salt);
            
            return hex_encode(key);
        });
    };
    
    size_t fails = run_tests_in_dir("test_data/kdf", test);
    
    test_report("kdf", 1, fails);
}
