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
size_t static_provider_weight(in string prov_name)
{
	/*
	* Prefer asm over C++, but prefer anything over OpenSSL or GNU MP; to use
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
		if (algo == m_algorithms.end()) // algo not found at all (no providers)
			return null;
		
		// If a provider is requested specifically, return it or fail entirely
		if (requested_provider != "")
		{
			auto prov = algo.second.find(requested_provider);
			if (prov != algo.second.end())
				return prov.second;
			return null;
		}
		
		const T prototype = null;
		string prototype_provider;
		size_t prototype_prov_weight = 0;
		
		const string pref_provider = m_pref_providers.get(algo_spec);
		
		for (auto i = algo.second.ptr; i != algo.second.end(); ++i)
		{
			// preferred prov exists, return immediately
			if (i.first == pref_provider)
				return i.second;
			
			const size_t prov_weight = static_provider_weight(i.first);
			
			if (prototype == null || prov_weight > prototype_prov_weight)
			{
				prototype = i.second;
				prototype_provider = i.first;
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
				
		if (algo.name != requested_name &&
		    m_aliases.find(requested_name) == m_aliases.end())
		{
			m_aliases[requested_name] = algo.name;
		}
		
		if (!m_algorithms[algo.name][provider])
			m_algorithms[algo.name][provider] = algo;
		//else
		//	delete algo;
		// todo: Manual Memory Management
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

		if (algo != m_algorithms.end())
		{
			auto provider = algo.second.ptr;
			
			while(provider != algo.second.end())
			{
				providers.push_back(provider.first);
				++provider;
			}
		}
		
		return providers;
	}

	/**
	* Clear the cache
	*/
	void clear_cache()
	{
		auto algo = m_algorithms.ptr;
		
		while(algo != m_algorithms.end())
		{
			auto provider = algo.second.ptr;
			
			while(provider != algo.second.end())
			{
				// delete provider.second;
				// todo: Manual Memory Management
				++provider;
			}
			
			++algo;
		}
		
		m_algorithms.clear();
	}

	~this() { clear_cache(); }
private:

	/*
	* Look for an algorithm implementation in the cache, also checking aliases
	* Assumes object lock is held
	*/
	auto find_algorithm(in string algo_spec)
	{
		auto algo = m_algorithms.find(algo_spec);
		
		// Not found? Check if a known alias
		if (algo == m_algorithms.end())
		{
			auto _alias = m_aliases.find(algo_spec);

			if (_alias != m_aliases.end())
				algo = m_algorithms.find(_alias.second);
		}
		
		return algo;
	}
	HashMap!(string, string) m_aliases;
	HashMap!(string, string) m_pref_providers;
	HashMap!(string, HashMap!(string, T)) m_algorithms;
}