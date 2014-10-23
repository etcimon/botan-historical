/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbkdf.pbkdf1;

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import std.datetime;
import botan.utils.exceptn;

/**
* PKCS #5 v1 PBKDF, aka PBKDF1
* Can only generate a key up to the size of the hash output.
* Unless needed for backwards compatability, use PKCS5_PBKDF2
*/
final class PKCS5_PBKDF1 : PBKDF
{
public:
	/**
	* Create a PKCS #5 instance using the specified hash function.
	* @param hash_in pointer to a hash function object to use
	*/
	this(HashFunction hash_input)
	{
		hash = hash_input;
	}

	@property string name() const
	{
		return "PBKDF1(" ~ hash.name ~ ")";
	}

	PBKDF clone() const
	{
		return new PKCS5_PBKDF1(hash.clone());
	}

	/*
	* Return a PKCS#5 PBKDF1 derived key
	*/
	Pair!(size_t, OctetString) key_derivation(size_t key_len,
	                                          in string passphrase,
	                                          in ubyte* salt, size_t salt_len,
	                                          size_t iterations,
	                                          Duration loop_for) const
	{
		if (key_len > hash.output_length)
			throw new Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");
		
		hash.update(passphrase);
		hash.update(salt, salt_len);
		Secure_Vector!ubyte key = hash.flush();
		
		const start = Clock.currTime();
		size_t iterations_performed = 1;
		
		while(true)
		{
			if (iterations == 0)
			{
				if (iterations_performed % 10000 == 0)
				{
					auto time_taken = Clock.currTime() - start;
					if (time_taken > loop_for)
						break;
				}
			}
			else if (iterations_performed == iterations)
				break;
			
			hash.update(key);
			hash.flushInto(&key[0]);
			
			++iterations_performed;
		}
		
		return Pair(iterations_performed,
		            OctetString(&key[0], std.algorithm.min(key_len, key.length)));
	}
private:
	Unique!HashFunction hash;
};

