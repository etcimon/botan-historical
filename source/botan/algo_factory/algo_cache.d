/*
* An algorithm cache (used by Algorithm_Factory)
* (C) 2008-2009,2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.algo_factory.algo_cache;

import botan.utils.types;
import botan.utils.multimap;
// import string;
import botan.utils.types;
import botan.utils.hashmap;
/**
* @param prov_name a provider name
* @return weight for this provider
*/
ubyte static_provider_weight(in string prov_name)
{
	/*
	* Prefer asm over D, but prefer anything over OpenSSL or GNU MP; to use
	* them, set the provider explicitly for the algorithms you want
	*/
	
	if (prov_name == "aes_isa") return 9;
	if (prov_name == "simd") return 8;
	if (prov_name == "asm") return 7;
	
	if (prov_name == "core") return 5;
	
	if (prov_name == "openssl") return 2;
	if (prov_name == "gmp") return 1;
	
	return 0; // other/unknown
}


/**
* Algorithm_Cache (used by Algorithm_Factory)
*/
struct Algorithm_Cache(T)
{
public:
	/**
	* Look for an algorithm implementation by a particular provider
	* @param algo_spec names the requested algorithm
	* @param pref_provider suggests a preferred provider
	* @return prototype object, or NULL
	*/
	const T get(in string algo_spec, in string requested_provider)
	{
		auto algo = find_algorithm(algo_spec);
		if (algo.length == 0) // algo not found at all (no providers)
			return null;
		
		// If a provider is requested specifically, return it or fail entirely
		if (requested_provider != "")
		{
			return algo.get(requested_provider);
		}

		const T prototype = null;
		string prototype_provider;
		size_t prototype_prov_weight = 0;
		
		const string pref_provider = m_pref_providers.get(algo_spec);

		if (algo.get(m_pref_providers))
			return algo[m_pref_providers];

		foreach (provider, instance; algo) 
		{			
			const ubyte prov_weight = static_provider_weight(provider);
			
			if (prototype == null || prov_weight > prototype_prov_weight)
			{
				prototype = instance;
				prototype_provider = provider;
				prototype_prov_weight = prov_weight;
			}
		}
		
		return prototype;
	}

	/**
	* Add a new algorithm implementation to the cache
	* @param algo the algorithm prototype object
	* @param requested_name how this name will be requested
	* @param provider_name is the name of the provider of this prototype
	*/
	void add(T algo,
	         in string requested_name,
	         in string provider)
	{
		if (!algo)
			return;
				
		if (algo.name != requested_name && m_aliases.get(requested_name) == null)
		{
			m_aliases[requested_name] = algo.name;
		}
		
		if (!m_algorithms[algo.name].get(provider))
			m_algorithms[algo.name][provider] = algo;

	}


	/**
	* Set the preferred provider for an algorithm
	* @param algo_spec names the algorithm
	* @param provider names the preferred provider
	*/
	void set_preferred_provider(in string algo_spec,
	                            in string provider)
	{		
		m_pref_providers[algo_spec] = provider;
	}

	/**
	* Find the providers of this algo (if any)
	* Return the list of providers of this algorithm
	* @param algo_name names the algorithm
	* @return list of providers of this algorithm
	*/
	Vector!string providers_of(in string algo_name)
	{
		
		Vector!string providers;

		string algo = algo_name;
		if (m_aliases.get(algo_name))
			algo = m_aliases[algo_name];

		if (!m_algorithms.get(algo))
			return Vector!string();

		foreach (provider, instance; m_algorithms[algo])
		{
			providers.push_back(provider);
		}
				
		return providers;
	}

	/**
	* Clear the cache
	*/
	void clear_cache()
	{
		/*
		foreach (provider, algorithms; m_algorithms)
		{
			foreach (name, instance; algorithms) {
				delete instance;
			}
		}*/

		/// Let the GC handle this
		m_algorithms.clear();
	}

	~this() { clear_cache(); }
private:

	/*
	* Look for an algorithm implementation in the cache, also checking aliases
	* Assumes object lock is held
	*/
	HashMap!(string, T) find_algorithm(in string algo_spec)
	{
		auto algo = m_algorithms.get(algo_spec);
		
		// Not found? Check if a known alias
		if (!algo)
		{
			auto _alias = m_aliases.get(algo_spec);

			if (_alias)
				algo = m_algorithms.get(_alias);
			else
				return HashMap!(string, T).init;
		}
		
		return algo;
	}
	HashMap!(string, string) m_aliases;
	HashMap!(string, string) m_pref_providers;

			// algo_name     //provider // instance
	HashMap!(string, HashMap!(string, T)) m_algorithms;
}