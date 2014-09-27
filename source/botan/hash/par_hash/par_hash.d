/*
* Parallel
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.par_hash;
import botan.parsing;
/*
* Update the hash
*/
void Parallel::add_data(in byte* input, size_t length)
{
	foreach (hash; hashes)
		 hash->update(input, length);
}

/*
* Finalize the hash
*/
void Parallel::final_result(byte* output)
{
	uint offset = 0;

	foreach (hash; hashes)
	{
		hash->flushInto(out + offset);
		offset += hash->output_length();
	}
}

/*
* Return output size
*/
size_t Parallel::output_length() const
{
	size_t sum = 0;

	foreach (hash; hashes)
		sum += hash->output_length();
	return sum;
}

/*
* Return the name of this type
*/
string Parallel::name() const
{
	Vector!( string ) names;

	foreach (hash; hashes)
		names.push_back(hash->name());

	return "Parallel(" + string_join(names, ',') + ")";
}

/*
* Return a clone of this object
*/
HashFunction* Parallel::clone() const
{
	Vector!( HashFunction* ) hash_copies;

	foreach (hash; hashes)
		hash_copies.push_back(hash->clone());

	return new Parallel(hash_copies);
}

/*
* Clear memory of sensitive data
*/
void Parallel::clear()
{
	foreach (hash; hashes)
		hash->clear();
}

/*
* Parallel Constructor
*/
Parallel::Parallel(in Vector!( HashFunction* ) hash_input) :
	hashes(hash_input)
{
}

/*
* Parallel Destructor
*/
Parallel::~Parallel()
{
	foreach (hash; hashes)
		delete hash;
}

}
