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
final class DynamicallyLoadedEngine : Engine
{
public:
    /**
    * @param lib_path = full pathname to DLL to load
    */
    this(in string library_path) 
    {
        m_engine = null;
        m_lib = new DynamicallyLoadedLibrary(library_path);
        
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


    this(in DynamicallyLoadedEngine);

    void opAssign(DynamicallyLoadedEngine);

    ~this()
    {
        delete m_engine;
        delete m_lib;
    }

    string providerName() const { return m_engine.providerName(); }

    BlockCipher findBlockCipher(in SCANName algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findBlockCipher(algo_spec, af);
    }

    StreamCipher findStreamCipher(in SCANName algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findStreamCipher(algo_spec, af);
    }

    HashFunction findHash(in SCANName algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findHash(algo_spec, af);
    }

    MessageAuthenticationCode findMac(in SCANName algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findMac(algo_spec, af);
    }

    PBKDF findPbkdf(in SCANName algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findPbkdf(algo_spec, af);
    }

    ModularExponentiator modExp(in BigInt n, powerMod.UsageHints hints) const
    {
        return m_engine.modExp(n, hints);
    }

    KeyedFilter getCipher(in string algo_spec, CipherDir dir, AlgorithmFactory af)
    {
        return m_engine.getCipher(algo_spec, dir, af);
    }

    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getKeyAgreementOp(key, rng);
    }

    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getSignatureOp(key, rng);
    }

    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getVerifyOp(key, rng);
    }

    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getEncryptionOp(key, rng);
    }

    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getDecryptionOp(key, rng);
    }

private:
    Dynamically_Loaded_Library m_lib;
    Engine m_engine;
}

private nothrow @nogc extern(C):

typedef Engine function() creator_func;
typedef uint function() module_version_func;