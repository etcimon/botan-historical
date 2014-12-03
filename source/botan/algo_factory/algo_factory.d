/*
* Algorithm Factory
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.algo_factory.algo_factory;

import botan.algo_factory.algo_cache;
import botan.utils.containers.multimap;
import botan.engine.engine;
import botan.utils.exceptn;

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;
import botan.pbkdf.pbkdf;

import std.algorithm;

import botan.utils.types;
// import string;
import botan.utils.types;
import botan.utils.memory : FreeListRef;


alias AlgorithmFactory = FreeListRef!AlgorithmFactoryImpl;

/**
* Algorithm Factory
*/
final class AlgorithmFactoryImpl
{
public:
    /**
    * Constructor
    */
    this() { }
    
    /**
    * Destructor
    */
    ~this()    { }
    
    /**
    * @param engine = to add (AlgorithmFactory takes ownership)
    */
    void addEngine(Engine engine)
    {
        clear_caches();
        m_engines.pushBack(engine);
    }
    
    /**
    * Clear out any cached objects
    */
    void clearCaches()
    {
        m_block_cipher_cache.clearCache();
        m_stream_cipher_cache.clearCache();
        m_hash_cache.clearCache();
        m_mac_cache.clearCache();
        m_pbkdf_cache.clearCache();
    }
    
    /**
    * Return the possible providers of a request
    * Note: assumes you don't have different types by the same name
    * @param algo_spec = the algorithm we are querying
    * @returns list of providers of this algorithm
    */
    Vector!string providersOf(in string algo_spec)
    {
        /* The checks with if (prototype_X(algo_spec)) have the effect of
        forcing a full search, since otherwise there might not be any
        providers at all in the cache.
        */
        
        if (prototypeBlockCipher(algo_spec))
            return m_block_cipher_cache.providersOf(algo_spec);
        else if (prototypeStreamCipher(algo_spec))
            return m_stream_cipher_cache.providersOf(algo_spec);
        else if (prototypeHashFunction(algo_spec))
            return m_hash_cache.providersOf(algo_spec);
        else if (prototypeMac(algo_spec))
            return m_mac_cache.providersOf(algo_spec);
        else if (prototypePbkdf(algo_spec))
            return m_pbkdf_cache.providersOf(algo_spec);
        else
            return Vector!string();
    }

    
    /**
    * Set the preferred provider for an algorithm
    * @param algo_spec = the algorithm we are setting a provider for
    * @param provider = the provider we would like to use
    */
    void setPreferredProvider(in string algo_spec, in string provider)
    {
        if (prototypeBlockCipher(algo_spec))
            m_block_cipher_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeStreamCipher(algo_spec))
            m_stream_cipher_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeHashFunction(algo_spec))
            m_hash_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeMac(algo_spec))
            m_mac_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypePbkdf(algo_spec))
            m_pbkdf_cache.setPreferredProvider(algo_spec, provider);
    }
    
    /**
    * Return the prototypical block cipher corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to const prototype object, ready to clone(), or NULL
    */
    BlockCipher prototypeBlockCipher(in string algo_spec, in string provider) const
    {
        return factory_prototype!BlockCipher(algo_spec, provider, engines, this, m_block_cipher_cache);
    }
    
    /**
    * Return a new block cipher corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to freshly created instance of the request algorithm
    */
    BlockCipher makeBlockCipher(in string algo_spec,
                                  in string provider)
    {
        if (const BlockCipher proto = prototypeBlockCipher(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
    
    /**
    * Add a new block cipher
    * @param algo = the algorithm to add
    * @param provider = the provider of this algorithm
    */
    void addBlockCipher(BlockCipher block_cipher, in string provider)
    {
        m_block_cipher_cache.add(block_cipher, block_cipher.name, provider);
    }
    
    /**
    * Return the prototypical stream cipher corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to const prototype object, ready to clone(), or NULL
    */
    StreamCipher prototypeStreamCipher(in string algo_spec, in string provider) const
    {
        return factory_prototype!StreamCipher(algo_spec, provider, engines, this, m_stream_cipher_cache);
    }

    
    /**
    * Return a new stream cipher corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to freshly created instance of the request algorithm
    */
    StreamCipher makeStreamCipher(in string algo_spec,
                                    in string provider)
    {
        if (const StreamCipher proto = prototypeStreamCipher(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }

    
    /**
    * Add a new stream cipher
    * @param algo = the algorithm to add
    * @param provider = the provider of this algorithm
    */
    void addStreamCipher(StreamCipher stream_cipher, in string provider)
    {
        m_stream_cipher_cache.add(stream_cipher, stream_cipher.name, provider);
    }
    
    /**
    * Return the prototypical object corresponding to this request (if found)
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to const prototype object, ready to clone(), or NULL
    */
    HashFunction prototypeHashFunction(in string algo_spec, in string provider) const
    {
        return factory_prototype!HashFunction(algo_spec, provider, engines, this, m_hash_cache);
    }

    
    /**
    * Return a new object corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to freshly created instance of the request algorithm
    */
    HashFunction makeHashFunction(in string algo_spec, in string provider)
    {
        if (const HashFunction proto = prototypeHashFunction(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
        
    /**
    * Add a new hash
    * @param algo = the algorithm to add
    * @param provider = the provider of this algorithm
    */
    void addHashFunction(HashFunction hash, in string provider)
    {
        m_hash_cache.add(hash, hash.name, provider);
    }
    
    /**
    * Return the prototypical object corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to const prototype object, ready to clone(), or NULL
    */
    MessageAuthenticationCode prototypeMac(in string algo_spec, in string provider) const
    {
        return factory_prototype!MessageAuthenticationCode(algo_spec, provider, engines, this, m_mac_cache);
    }
    
    /**
    * Return a new object corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to freshly created instance of the request algorithm
    */
    MessageAuthenticationCode makeMac(in string algo_spec, in string provider)
    {
        if (const MessageAuthenticationCode proto = prototypeMac(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }

    
    /**
    * @param algo = the algorithm to add
    * @param provider = the provider of this algorithm
    */
    void addMac(MessageAuthenticationCode mac, in string provider)
    {
        m_mac_cache.add(mac, mac.name, provider);
    }

    
    /**
    * Return the prototypical object corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to const prototype object, ready to clone(), or NULL
    */
    PBKDF prototypePbkdf(in string algo_spec, in string provider) const
    {
        return factory_prototype!PBKDF(algo_spec, provider, engines, this, m_pbkdf_cache);
    }

    
    /**
    * Add a new PBKDF
    * Returns a new object corresponding to this request
    * @param algo_spec = the algorithm we want
    * @param provider = the provider we would like to use
    * @returns pointer to freshly created instance of the request algorithm
    */
    PBKDF makePbkdf(in string algo_spec, in string provider)
    {
        if (const PBKDF proto = prototypePbkdf(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
    
    /**
    * @param algo = the algorithm to add
    * @param provider = the provider of this algorithm
    */
    void addPbkdf(PBKDF pbkdf, in string provider)
    {
        m_pbkdf_cache.add(pbkdf, pbkdf.name, provider);
    }

    
    @property Vector!Engine engines() {
        return m_engines;
    }

private:
    Engine getEngineN(size_t n) const
    {
        // Get an engine out of the list
        if (n >= m_engines.length)
            return null;
        return m_engines[n];
    }
    
    Vector!Engine m_engines;
    
    Algorithm_Cache!BlockCipher m_block_cipher_cache;
    Algorithm_Cache!StreamCipher m_stream_cipher_cache;
    Algorithm_Cache!HashFunction m_hash_cache;
    Algorithm_Cache!MessageAuthenticationCode m_mac_cache;
    Algorithm_Cache!PBKDF m_pbkdf_cache;
}

private:

/*
* Template functions for the factory prototype/search algorithm
*/
T engineGetAlgo(T)(Engine, in SCANName, AlgorithmFactory)
{ static assert(false, "Invalid engine"); }

BlockCipher engineGetAlgo(T : BlockCipher, U : SCANName)(Engine engine, 
                                                            auto ref U request, 
                                                            AlgorithmFactory af)
{ return engine.findBlockCipher(request, af); }

StreamCipher engineGetAlgo(T : StreamCipher, U : SCANName)(Engine engine, 
                                                              auto ref U request, 
                                                              AlgorithmFactory af)
{ return engine.findStreamCipher(request, af); }

HashFunction engineGetAlgo(T : HashFunction, U : SCANName)(Engine engine, 
                                                              auto ref U request, 
                                                              AlgorithmFactory af)
{ return engine.findHash(request, af); }

MessageAuthenticationCode engineGetAlgo(T : MessageAuthenticationCode, U : SCANName)(Engine engine, 
                                                                                        auto ref U request,
                                                                                        AlgorithmFactory af)
{ return engine.findMac(request, af); }

PBKDF engineGetAlgo(T : PBKDF, U : SCANName)(Engine engine, 
                                                auto ref U request, 
                                                AlgorithmFactory af)
{ return engine.findPbkdf(request, af); }

T factoryPrototype(T)(in string algo_spec,
                             in string provider,
                             in Vector!( Engine ) engines,
                             AlgorithmFactory af,
                             Algorithm_Cache!T cache) const {
    if (const T cache_hit = cache.get(algo_spec, provider))
        return cache_hit;

    SCANName scan_name = SCANName(algo_spec);

    if (scan_name.cipherMode() != "")
        return null;

    foreach (const engine; engines[])
    {
        if (provider == "" || engine.provider_name == provider)
        {
            if (T impl = af.engineGetAlgo!T(engine, scan_name, af))
                cache.add(impl, algo_spec, engine.providerName());
        }
    }

    return cache.get(algo_spec, provider);
}
