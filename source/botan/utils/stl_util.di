/*
* STL Utility Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import vector;
import string;
import map;
 Vector!byte to_byte_vector(in string s)
{
	return Vector!byte(cast(in byte*)(s[0]),
									 cast(in byte*)(s[s.size()]));
}

/*
* Searching through a HashMap
* @param mapping the map to search
* @param key is what to look for
* @param null_result is the value to return if key is not in mapping
* @return mapping[key] or null_result
*/
template<typename K, typename V>
 V search_map(in HashMap<K, V> mapping,
						  const K& key,
						  const V& null_result = V())
{
	auto i = mapping.find(key);
	if (i == mapping.end())
		return null_result;
	return i.second;
}

template<typename K, typename V, typename R>
 R search_map(in HashMap<K, V> mapping, const K& key,
						  const R& null_result, const R& found_result)
{
	auto i = mapping.find(key);
	if (i == mapping.end())
		return null_result;
	return found_result;
}

/*
* Insert a key/value pair into a multimap
*/
template<typename K, typename V>
void multimap_insert(std::multimap<K, V>& multimap,
							const K& key, const V& value)
{
#if defined(BOTAN_BUILD_COMPILER_IS_SUN_STUDIO)
	// Work around a strange bug in Sun Studio
	multimap.insert(Pair<const K, V>(key, value));
#else
	multimap.insert(Pair(key, value));
#endif
}

/**
* Existence check for values
*/
template<typename T>
bool value_exists(in Vector!T vec,
						const T& val)
{
	for (size_t i = 0; i != vec.size(); ++i)
		if (vec[i] == val)
			return true;
	return false;
}

template<typename T, typename Pred>
void map_remove_if (Pred pred, T& assoc)
{
	auto i = assoc.begin();
	while(i != assoc.end())
	{
		if (pred(i.first))
			assoc.erase(i++);
		else
			i++;
	}
}