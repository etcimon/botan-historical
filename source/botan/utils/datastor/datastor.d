/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.datastor.datastor;

public import botan.utils.exceptn;
import botan.utils.parsing;
import botan.codec.hex;
import botan.utils.multimap;
import botan.alloc.zeroize;
import functional;
// import string;
import botan.utils.types;
import botan.utils.hashmap;

/**
* Data Store
*/
struct Data_Store
{
public:
	/*
	* Data_Store Equality Comparison
	*/
	bool opEquals(in Data_Store other) const
	{
		return (m_contents == other.m_contents);
	}

	/*
	* Search based on an arbitrary predicate
	*/
	MultiMap!(string, string) search_for(bool delegate(string, string) predicate) const
	{
		MultiMap!(string, string) output;

		foreach (key, val; m_contents)
			if (predicate(key, val))
				output.insert(key, val);
		
		return output;
	}

	/*
	* Search based on key equality
	*/
	Vector!string get(in string looking_for) const
	{
		Vector!string output;
		foreach (el; m_contents)
			if (looking_for == el.first)
				output.push_back(el.second);
		return output;
	}


	/*
	* Get a single atom
	*/
	string get1(in string key) const
	{
		Vector!string vals = get(key);
		
		if (vals.empty)
			throw new Invalid_State("get1: No values set for " ~ key);
		if (vals.length > 1)
			throw new Invalid_State("get1: More than one value for " ~ key);
		
		return vals[0];
	}

	string get1(in string key,
	            in string default_value) const
	{
		Vector!string vals = get(key);
		
		if (vals.length > 1)
			throw new Invalid_State("get1: More than one value for " ~ key);
		
		if (vals.empty)
			return default_value;
		
		return vals[0];
	}

	/*
	* Get a single std::vector atom
	*/
	Vector!ubyte
		get1_memvec(in string key) const
	{
		Vector!string vals = get(key);
		
		if (vals.empty)
			return Vector!ubyte();
		
		if (vals.length > 1)
			throw new Invalid_State("get1_memvec: Multiple values for " ~
			                        key);
		
		return hex_decode(vals[0]);
	}

	/*
	* Get a single uint atom
	*/
	uint get1_uint(in string key,
	               uint default_val) const
	{
		Vector!string vals = get(key);
		
		if (vals.empty)
			return default_val;
		else if (vals.length > 1)
			throw new Invalid_State("get1_uint: Multiple values for " ~
			                        key);
		
		return to!uint(vals[0]);
	}

	/*
	* Check if this key has at least one value
	*/
	bool has_value(in string key) const
	{
		return (m_contents.lower_bound(key) != m_contents.end());
	}


	
	/*
	* Insert a single key and value
	*/
	void add(in string key, in string val)
	{
		multimap_insert(m_contents, key, val);
	}
	
	/*
	* Insert a single key and value
	*/
	void add(in string key, uint val)
	{
		add(key, to!string(val));
	}
	
	/*
	* Insert a single key and value
	*/
	void add(in string key, in Secure_Vector!ubyte val)
	{
		add(key, hex_encode(&val[0], val.length));
	}
	
	void add(in string key, in Vector!ubyte val)
	{
		add(key, hex_encode(&val[0], val.length));
	}
	
	/*
	* Insert a mapping of key/value pairs
	*/
	void add(in MultiMap!(string, string) input)
	{
		foreach (k, const ref v; input)
			m_contents.insert(k, v);
	}

private:
	MultiMap!(string, string) m_contents;
}