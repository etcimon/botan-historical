/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.datastor;
import botan.exceptn;
import botan.parsing;
import botan.hex;
import botan.internal.stl_util;
/*
* Data_Store Equality Comparison
*/
bool Data_Store::operator==(in Data_Store other) const
{
	return (contents == other.contents);
}

/*
* Check if this key has at least one value
*/
bool Data_Store::has_value(in string key) const
{
	return (contents.lower_bound(key) != contents.end());
}

/*
* Search based on an arbitrary predicate
*/
std::multimap<string, string> Data_Store::search_for(
	bool delegate(string, string) predicate) const
{
	std::multimap<string, string> out;

	for (auto i = contents.begin(); i != contents.end(); ++i)
		if (predicate(i.first, i.second))
			out.insert(Pair(i.first, i.second));

	return out;
}

/*
* Search based on key equality
*/
Vector!string Data_Store::get(in string looking_for) const
{
	Vector!string out;
	auto range = contents.equal_range(looking_for);
	for (auto i = range.first; i != range.second; ++i)
		out.push_back(i.second);
	return out;
}

/*
* Get a single atom
*/
string Data_Store::get1(in string key) const
{
	Vector!string vals = get(key);

	if (vals.empty())
		throw new Invalid_State("Data_Store::get1: No values set for " + key);
	if (vals.size() > 1)
		throw new Invalid_State("Data_Store::get1: More than one value for " + key);

	return vals[0];
}

string Data_Store::get1(in string key,
						in string default_value) const
{
	Vector!string vals = get(key);

	if (vals.size() > 1)
		throw new Invalid_State("Data_Store::get1: More than one value for " + key);

	if (vals.empty())
		return default_value;

	return vals[0];
}

/*
* Get a single std::vector atom
*/
Vector!byte
Data_Store::get1_memvec(in string key) const
{
	Vector!string vals = get(key);

	if (vals.empty())
		return Vector!byte();

	if (vals.size() > 1)
		throw new Invalid_State("Data_Store::get1_memvec: Multiple values for " +
								  key);

	return hex_decode(vals[0]);
}

/*
* Get a single uint atom
*/
uint Data_Store::get1_uint(in string key,
										 uint default_val) const
{
	Vector!string vals = get(key);

	if (vals.empty())
		return default_val;
	else if (vals.size() > 1)
		throw new Invalid_State("Data_Store::get1_uint: Multiple values for " +
								  key);

	return to_uint(vals[0]);
}

/*
* Insert a single key and value
*/
void Data_Store::add(in string key, in string val)
{
	multimap_insert(contents, key, val);
}

/*
* Insert a single key and value
*/
void Data_Store::add(in string key, uint val)
{
	add(key, std::to_string(val));
}

/*
* Insert a single key and value
*/
void Data_Store::add(in string key, in SafeVector!byte val)
{
	add(key, hex_encode(&val[0], val.size()));
}

void Data_Store::add(in string key, in Vector!byte val)
{
	add(key, hex_encode(&val[0], val.size()));
}

/*
* Insert a mapping of key/value pairs
*/
void Data_Store::add(in std::multimap<string, string> input)
{
	std::multimap<string, string>::const_iterator i = input.begin();
	while(i != input.end())
	{
		contents.insert(*i);
		++i;
	}
}

}
