/*
* Parallel Hash
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.par_hash;

import botan.hash.hash;
import vector;
import botan.utils.parsing;

/**
* Parallel Hashes
*/
class Parallel : HashFunction
{
public:
	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		foreach (hash; hashes)
			hash.clear();
	}

	/*
	* Return the name of this type
	*/
	string name() const
	{
		Vector!string names;
		
		foreach (hash; hashes)
			names.push_back(hash.name());
		
		return "Parallel(" ~ string_join(names, ',') ~ ")";
	}

	/*
	* Return a clone of this object
	*/
	HashFunction clone() const
	{
		Vector!( HashFunction ) hash_copies;
		
		foreach (hash; hashes)
			hash_copies.push_back(hash.clone());
		
		return new Parallel(hash_copies);
	}

	/*
	* Return output size
	*/
	size_t output_length() const
	{
		size_t sum = 0;
		
		foreach (hash; hashes)
			sum += hash.output_length();
		return sum;
	}

	/**
	* Constructor
	* @param hash_input a set of hashes to compute in parallel
	*/
	this(in Vector!( HashFunction ) hash_input)
	{
		hashes = hash_input;
	}

	/*
	* Parallel Destructor
	*/
	~this()
	{
		foreach (hash; hashes)
			delete hash;
	}
private:
	/*
	* Update the hash
	*/
	void add_data(in ubyte* input, size_t length)
	{
		foreach (hash; hashes)
			hash.update(input, length);
	}

	/*
	* Finalize the hash
	*/
	void final_result(ubyte* output)
	{
		uint offset = 0;
		
		foreach (hash; hashes)
		{
			hash.flushInto(output + offset);
			offset += hash.output_length();
		}
	}
	Vector!( HashFunction ) hashes;
};