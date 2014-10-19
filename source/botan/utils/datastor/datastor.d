/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.datastor.datastor;

import botan.alloc.secmem;
import functional;
import utility;
import string;
import vector;
import map;
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
		return (contents == other.contents);
	}

	/*
	* Search based on an arbitrary predicate
	*/
	MultiMap!(string, string) search_for(
		bool delegate(string, string) predicate) const
	{
		MultiMap!(string, string) output;

		foreach (el; contents)
			if (predicate(el.first, el.second))
				output.insert(Pair(i.first, i.second));
		
		return output;
	}

	/*
	* Search based on key equality
	*/
	Vector!string get(in string looking_for) const
	{
		Vector!string output;
		foreach (el; contents)
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
		
		if (vals.empty())
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
		
		if (vals.empty())
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
		
		if (vals.empty())
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
		
		if (vals.empty())
			return default_val;
		else if (vals.length > 1)
			throw new Invalid_State("get1_uint: Multiple values for " ~
			                        key);
		
		return to_uint(vals[0]);
	}

	/*
	* Check if this key has at least one value
	*/
	bool has_value(in string key) const
	{
		return (contents.lower_bound(key) != contents.end());
	}


	
	/*
	* Insert a single key and value
	*/
	void add(in string key, in string val)
	{
		multimap_insert(contents, key, val);
	}
	
	/*
	* Insert a single key and value
	*/
	void add(in string key, uint val)
	{
		add(key, std.conv.to!string(val));
	}
	
	/*
	* Insert a single key and value
	*/
	void add(in string key, in SafeVector!ubyte val)
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
		foreach (el; input)
			contents.insert(el);
	}

private:
	MultiMap!(string, string) contents;
};



import botan.utils.datastor.datastor;
import botan.utils.exceptn;
import botan.utils.parsing;
import botan.codec.hex;
import botan.internal.stl_util;












