/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pbkdf;
import botan.hash;
/**
* PKCS #5 v1 PBKDF, aka PBKDF1
* Can only generate a key up to the size of the hash output.
* Unless needed for backwards compatability, use PKCS5_PBKDF2
*/
class PKCS5_PBKDF1 : PBKDF
{
	public:
		/**
		* Create a PKCS #5 instance using the specified hash function.
		* @param hash_in pointer to a hash function object to use
		*/
		PKCS5_PBKDF1(HashFunction hash_input) : hash(hash_input) {}

		string name() const
		{
			return "PBKDF1(" ~ hash.name() ~ ")";
		}

		PBKDF clone() const
		{
			return new PKCS5_PBKDF1(hash.clone());
		}

		Pair!(size_t, OctetString)
			key_derivation(size_t output_len,
								in string passphrase,
								in ubyte* salt, size_t salt_len,
								size_t iterations,
								override std::chrono::milliseconds msec) const;
	private:
		Unique!HashFunction hash;
};