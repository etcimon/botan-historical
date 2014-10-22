/*
* Algorithm Factory
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.algo_factory.algo_factory;

import botan.algo_factory.algo_cache;
import botan.internal.stl_util;
import botan.engine.engine;
import botan.utils.exceptn;

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;
import botan.pbkdf.pbkdf;

import std.algorithm;

import botan.utils.types;
import string;
import vector;
import botan.utils.memory : FreeListRef;


alias AlgorithmFactory = FreeListRef!AlgorithmFactoryImpl;

/**
* Algorithm Factory
*/
class AlgorithmFactoryImpl
{
public:
	/**
	* Constructor
	*/
	this() { }
	
	/**
	* Destructor
	*/
	~this()	{ }
	
	/**
	* @param engine to add (AlgorithmFactory takes ownership)
	*/
	void add_engine(Engine engine)
	{
		clear_caches();
		engines.push_back(engine);
	}
	
	/**
	* Clear out any cached objects
	*/
	void clear_caches()
	{
		block_cipher_cache.clear_cache();
		stream_cipher_cache.clear_cache();
		hash_cache.clear_cache();
		mac_cache.clear_cache();
		pbkdf_cache.clear_cache();
	}
	
	/**
	* Return the possible providers of a request
	* Note: assumes you don't have different types by the same name
	* @param algo_spec the algorithm we are querying
	* @returns list of providers of this algorithm
	*/
	Vector!string providers_of(in string algo_spec)
	{
		/* The checks with if (prototype_X(algo_spec)) have the effect of
		forcing a full search, since otherwise there might not be any
		providers at all in the cache.
		*/
		
		if (prototype_block_cipher(algo_spec))
			return block_cipher_cache.providers_of(algo_spec);
		else if (prototype_stream_cipher(algo_spec))
			return stream_cipher_cache.providers_of(algo_spec);
		else if (prototype_hash_function(algo_spec))
			return hash_cache.providers_of(algo_spec);
		else if (prototype_mac(algo_spec))
			return mac_cache.providers_of(algo_spec);
		else if (prototype_pbkdf(algo_spec))
			return pbkdf_cache.providers_of(algo_spec);
		else
			return Vector!string();
	}

	
	/**
	* Set the preferred provider for an algorithm
	* @param algo_spec the algorithm we are setting a provider for
	* @param provider the provider we would like to use
	*/
	void set_preferred_provider(in string algo_spec,
	                            in string provider)
	{
		if (prototype_block_cipher(algo_spec))
			block_cipher_cache.set_preferred_provider(algo_spec, provider);
		else if (prototype_stream_cipher(algo_spec))
			stream_cipher_cache.set_preferred_provider(algo_spec, provider);
		else if (prototype_hash_function(algo_spec))
			hash_cache.set_preferred_provider(algo_spec, provider);
		else if (prototype_mac(algo_spec))
			mac_cache.set_preferred_provider(algo_spec, provider);
		else if (prototype_pbkdf(algo_spec))
			pbkdf_cache.set_preferred_provider(algo_spec, provider);
	}
	
	/**
	* Return the prototypical block cipher corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to const prototype object, ready to clone(), or NULL
	*/
	const BlockCipher
		prototype_block_cipher(in string algo_spec,
		                       in string provider)
	{
		return factory_prototype!BlockCipher(algo_spec, provider, engines,
		                                     this, *block_cipher_cache);
	}
	
	/**
	* Return a new block cipher corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to freshly created instance of the request algorithm
	*/
	BlockCipher make_block_cipher(in string algo_spec,
	                              in string provider)
	{
		if (const BlockCipher proto = prototype_block_cipher(algo_spec, provider))
			return proto.clone();
		throw new Algorithm_Not_Found(algo_spec);
	}
	
	/**
	* Add a new block cipher
	* @param algo the algorithm to add
	* @param provider the provider of this algorithm
	*/
	void add_block_cipher(BlockCipher block_cipher,
	                      in string provider)
	{
		block_cipher_cache.add(block_cipher, block_cipher.name(), provider);
	}
	
	/**
	* Return the prototypical stream cipher corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to const prototype object, ready to clone(), or NULL
	*/
	const StreamCipher 
		prototype_stream_cipher(in string algo_spec,
		                        in string provider)
	{
		return factory_prototype!StreamCipher(algo_spec, provider, engines,
		                                      this, *stream_cipher_cache);
	}

	
	/**
	* Return a new stream cipher corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to freshly created instance of the request algorithm
	*/
	StreamCipher make_stream_cipher(in string algo_spec,
	                                in string provider)
	{
		if (const StreamCipher proto = prototype_stream_cipher(algo_spec, provider))
			return proto.clone();
		throw new Algorithm_Not_Found(algo_spec);
	}

	
	/**
	* Add a new stream cipher
	* @param algo the algorithm to add
	* @param provider the provider of this algorithm
	*/
	void add_stream_cipher(StreamCipher stream_cipher,
	                       in string provider)
	{
		stream_cipher_cache.add(stream_cipher, stream_cipher.name(), provider);
	}
	
	/**
	* Return the prototypical object corresponding to this request (if found)
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to const prototype object, ready to clone(), or NULL
	*/
	const HashFunction
		prototype_hash_function(in string algo_spec,
		                        in string provider)
	{
		return factory_prototype!HashFunction(algo_spec, provider, engines,
		                                      this, *hash_cache);
	}

	
	/**
	* Return a new object corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to freshly created instance of the request algorithm
	*/
	HashFunction make_hash_function(in string algo_spec,
	                                in string provider)
	{
		if (const HashFunction proto = prototype_hash_function(algo_spec, provider))
			return proto.clone();
		throw new Algorithm_Not_Found(algo_spec);
	}
		
	/**
	* Add a new hash
	* @param algo the algorithm to add
	* @param provider the provider of this algorithm
	*/
	void add_hash_function(HashFunction hash,
	                       in string provider)
	{
		hash_cache.add(hash, hash.name(), provider);
	}
	
	/**
	* Return the prototypical object corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to const prototype object, ready to clone(), or NULL
	*/
	const MessageAuthenticationCode
		prototype_mac(in string algo_spec,
		              in string provider)
	{
		return factory_prototype!MessageAuthenticationCode(algo_spec, provider,
		                                                   engines,
		                                                   this, *mac_cache);
	}
	
	/**
	* Return a new object corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to freshly created instance of the request algorithm
	*/
	MessageAuthenticationCode make_mac(in string algo_spec,
	                                   in string provider)
	{
		if (const MessageAuthenticationCode proto = prototype_mac(algo_spec, provider))
			return proto.clone();
		throw new Algorithm_Not_Found(algo_spec);
	}

	
	/**
	* @param algo the algorithm to add
	* @param provider the provider of this algorithm
	*/
	void add_mac(MessageAuthenticationCode mac,
	             in string provider)
	{
		mac_cache.add(mac, mac.name(), provider);
	}

	
	/**
	* Return the prototypical object corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to const prototype object, ready to clone(), or NULL
	*/
	const PBKDF prototype_pbkdf(in string algo_spec,
	                            in string provider)
	{
		return factory_prototype!PBKDF(algo_spec, provider,
		                               engines,
		                               this, *pbkdf_cache);
	}

	
	/**
	* Add a new PBKDF
	* Returns a new object corresponding to this request
	* @param algo_spec the algorithm we want
	* @param provider the provider we would like to use
	* @returns pointer to freshly created instance of the request algorithm
	*/
	PBKDF make_pbkdf(in string algo_spec,
	                 in string provider)
	{
		if (const PBKDF proto = prototype_pbkdf(algo_spec, provider))
			return proto.clone();
		throw new Algorithm_Not_Found(algo_spec);
	}
	
	/**
	* @param algo the algorithm to add
	* @param provider the provider of this algorithm
	*/
	void add_pbkdf(PBKDF pbkdf,
	               in string provider)
	{
		pbkdf_cache.add(pbkdf, pbkdf.name(), provider);
	}

	
	/**
	* An iterator for the engines in this factory
	* @deprecated Avoid in new code
	*/
	class Engine_Iterator
	{
	public:
		/**
		* @return next engine in the sequence
		*/
		Engine next() { return af.get_engine_n(n++); }
		
		/**
		* @param a an algorithm factory
		*/
		this(AlgorithmFactory a) { af = a; n = 0; }
	private:
		const AlgorithmFactory af;
		size_t n;
	}

private:
	Engine get_engine_n(size_t n) const
	{
		// Get an engine out of the list
		if (n >= engines.length)
			return null;
		return engines[n];
	}
	
	Vector!Engine engines;
	
	Algorithm_Cache!BlockCipher block_cipher_cache;
	Algorithm_Cache!StreamCipher stream_cipher_cache;
	Algorithm_Cache!HashFunction hash_cache;
	Algorithm_Cache!MessageAuthenticationCode mac_cache;
	Algorithm_Cache!PBKDF pbkdf_cache;
};

private:

/*
* Template functions for the factory prototype/search algorithm
*/
T engine_get_algo(T)(Engine,
					 const ref SCAN_Name,
					 AlgorithmFactory)
{ static assert(false, "Invalid engine"); }

BlockCipher engine_get_algo(T : BlockCipher)(Engine engine,
							  const ref SCAN_Name request,
							  AlgorithmFactory af)
{ return engine.find_block_cipher(request, af); }

StreamCipher engine_get_algo(T : StreamCipher)(Engine engine,
										const ref SCAN_Name request,
										AlgorithmFactory af)
{ return engine.find_stream_cipher(request, af); }

HashFunction engine_get_algo(T : HashFunction)(Engine engine,
										const ref SCAN_Name request,
										AlgorithmFactory af)
{ return engine.find_hash(request, af); }

MessageAuthenticationCode engine_get_algo(T : MessageAuthenticationCode)(Engine engine,
														 const ref SCAN_Name request,
														 AlgorithmFactory af)
{ return engine.find_mac(request, af); }

PBKDF engine_get_algo(T : PBKDF)(Engine engine,
							  const ref SCAN_Name request,
							  AlgorithmFactory af)
{ return engine.find_pbkdf(request, af); }

const T factory_prototype(T)(in string algo_spec,
									in string provider,
									in Vector!( Engine ) engines,
									AlgorithmFactory af,
									Algorithm_Cache!T cache)
{
	if (const T cache_hit = cache.get(algo_spec, provider))
		return cache_hit;

	SCAN_Name scan_name(algo_spec);

	if (scan_name.cipher_mode() != "")
		return null;

	for (size_t i = 0; i != engines.length; ++i)
	{
		if (provider == "" || engines[i].provider_name() == provider)
		{
			if (T impl = af.engine_get_algo!T(engines[i], scan_name, af))
				cache.add(impl, algo_spec, engines[i].provider_name());
		}
	}

	return cache.get(algo_spec, provider);
}
