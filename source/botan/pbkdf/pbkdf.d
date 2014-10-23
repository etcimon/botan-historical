/*
* PBKDF
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbkdf.pbkdf;

import botan.algo_base.symkey;
import std.datetime;
/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*/
class PBKDF
{
public:

	~this() {}

	/**
	* @return new instance of this same algorithm
	*/
	abstract PBKDF clone() const;

	abstract @property string name() const;

	/**
	* Derive a key from a passphrase
	* @param output_len the desired length of the key to produce
	* @param passphrase the password to derive the key from
	* @param salt a randomly chosen salt
	* @param salt_len length of salt in bytes
	* @param iterations the number of iterations to use (use 10K or more)
	*/
	final OctetString derive_key(size_t output_len,
	                       in string passphrase,
	                       in ubyte* salt, size_t salt_len,
	                       size_t iterations) const
	{
		if (iterations == 0)
			throw new Invalid_Argument(name ~ ": Invalid iteration count");
		
		auto derived = key_derivation(output_len, passphrase,
		                              salt, salt_len, iterations,
		                              Duration(0));
		
		assert(derived.first == iterations,
		             "PBKDF used the correct number of iterations");
		
		return derived.second;
	}

	/**
	* Derive a key from a passphrase
	* @param output_len the desired length of the key to produce
	* @param passphrase the password to derive the key from
	* @param salt a randomly chosen salt
	* @param iterations the number of iterations to use (use 10K or more)
	*/
	final OctetString derive_key(Alloc)(size_t output_len,
								  in string passphrase,
								  ref const Vector!( ubyte, Alloc ) salt,
								  size_t iterations) const
	{
		return derive_key(output_len, passphrase, &salt[0], salt.length, iterations);
	}

	/**
	* Derive a key from a passphrase
	* @param output_len the desired length of the key to produce
	* @param passphrase the password to derive the key from
	* @param salt a randomly chosen salt
	* @param salt_len length of salt in bytes
	* @param loop_for is how long to run the PBKDF
	* @param iterations is set to the number of iterations used
	*/
	final OctetString derive_key(size_t output_len,
	                       in string passphrase,
	                       in ubyte* salt, size_t salt_len,
	                       Duration loop_for,
	                       ref size_t iterations) const
	{
		auto derived = key_derivation(output_len, passphrase, salt, salt_len, 0, loop_for);
		
		iterations = derived.first;
		
		return derived.second;
	}

	/**
	* Derive a key from a passphrase using a certain amount of time
	* @param output_len the desired length of the key to produce
	* @param passphrase the password to derive the key from
	* @param salt a randomly chosen salt
	* @param loop_for is how long to run the PBKDF
	* @param iterations is set to the number of iterations used
	*/
	final OctetString derive_key(Alloc)(size_t output_len,
								  in string passphrase,
								  ref const Vector!( ubyte, Alloc ) salt,
	                              Duration loop_for,
								  ref size_t iterations) const
	{
		return derive_key(output_len, passphrase, &salt[0], salt.length, loop_for, iterations);
	}

	/**
	* Derive a key from a passphrase for a number of iterations
	* specified by either iterations or if iterations == 0 then
	* running until seconds time has elapsed.
	*
	* @param output_len the desired length of the key to produce
	* @param passphrase the password to derive the key from
	* @param salt a randomly chosen salt
	* @param salt_len length of salt in bytes
	* @param iterations the number of iterations to use (use 10K or more)
	* @param loop_for if iterations is zero, then instead the PBKDF is
	*		  run until duration has passed.
	* @return the number of iterations performed and the derived key
	*/
	abstract Pair!(size_t, OctetString)
		key_derivation(size_t output_len,
							in string passphrase,
							in ubyte* salt, size_t salt_len,
							size_t iterations,
		               Duration loop_for) const;
};


import std.exception;
