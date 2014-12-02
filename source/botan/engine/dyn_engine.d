/**
* Dynamically Loaded Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.dyn_engine;

import botan.engine.engine;
import botan.utils.dyn_load.dyn_load;

/**
* Dynamically_Loaded_Engine just proxies the requests to the underlying
* Engine object, and handles load/unload details
*/
final class Dynamically_Loaded_Engine : Engine
{
public:
    /**
    * @param lib_path full pathname to DLL to load
    */
    this(in string library_path) 
    {
        m_engine = null;
        m_lib = new Dynamically_Loaded_Library(library_path);
        
        try
        {
            module_version_func get_version = m_lib.resolve!module_version_func("module_version");
            
            const uint mod_version = get_version();
            
            if (mod_version != 20101003)
                throw new Exception("Incompatible version in " ~ library_path ~ " of " ~ to!string(mod_version));
            
            creator_func creator = m_lib.resolve!creator_func("create_engine");
            
            m_engine = creator();

            if (!m_engine)
                throw new Exception("Creator function in " ~ library_path ~ " failed");
        }
        catch (Throwable)
        {
            delete lib;
            lib = null;
            throw new Exception();
        }
    }


    this(in Dynamically_Loaded_Engine);

    void opAssign(Dynamically_Loaded_Engine);

    ~this()
    {
        delete m_engine;
        delete m_lib;
    }

    string provider_name() const { return m_engine.provider_name(); }

    BlockCipher find_block_cipher(in SCAN_Name algo_spec, Algorithm_Factory af) const
    {
        return m_engine.find_block_cipher(algo_spec, af);
    }

    StreamCipher find_stream_cipher(in SCAN_Name algo_spec, Algorithm_Factory af) const
    {
        return m_engine.find_stream_cipher(algo_spec, af);
    }

    HashFunction find_hash(in SCAN_Name algo_spec, Algorithm_Factory af) const
    {
        return m_engine.find_hash(algo_spec, af);
    }

    MessageAuthenticationCode find_mac(in SCAN_Name algo_spec, Algorithm_Factory af) const
    {
        return m_engine.find_mac(algo_spec, af);
    }

    PBKDF find_pbkdf(in SCAN_Name algo_spec, Algorithm_Factory af) const
    {
        return m_engine.find_pbkdf(algo_spec, af);
    }

    Modular_Exponentiator mod_exp(in BigInt n, power_mod.Usage_Hints hints) const
    {
        return m_engine.mod_exp(n, hints);
    }

    Keyed_Filter get_cipher(in string algo_spec, Cipher_Dir dir, Algorithm_Factory af)
    {
        return m_engine.get_cipher(algo_spec, dir, af);
    }

    Key_Agreement get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const
    {
        return m_engine.get_key_agreement_op(key, rng);
    }

    Signature get_signature_op(in Private_Key key, RandomNumberGenerator rng) const
    {
        return m_engine.get_signature_op(key, rng);
    }

    Verification get_verify_op(in Public_Key key, RandomNumberGenerator rng) const
    {
        return m_engine.get_verify_op(key, rng);
    }

    Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const
    {
        return m_engine.get_encryption_op(key, rng);
    }

    Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const
    {
        return m_engine.get_decryption_op(key, rng);
    }

private:
    Dynamically_Loaded_Library m_lib;
    Engine m_engine;
}

private nothrow @nogc extern(C):

typedef Engine function() creator_func;
typedef uint function() module_version_func;