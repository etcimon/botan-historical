/*
* PBKDF
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_base.symkey;
import chrono;
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

		abstract string name() const;

		/**
		* Derive a key from a passphrase
		* @param output_len the desired length of the key to produce
		* @param passphrase the password to derive the key from
		* @param salt a randomly chosen salt
		* @param salt_len length of salt in bytes
		* @param iterations the number of iterations to use (use 10K or more)
		*/
		OctetString derive_key(size_t output_len,
									  in string passphrase,
									  in byte* salt, size_t salt_len,
									  size_t iterations) const;

		/**
		* Derive a key from a passphrase
		* @param output_len the desired length of the key to produce
		* @param passphrase the password to derive the key from
		* @param salt a randomly chosen salt
		* @param iterations the number of iterations to use (use 10K or more)
		*/
		OctetString derive_key(Alloc)(size_t output_len,
									  in string passphrase,
									  const Vector!( byte, Alloc )& salt,
									  size_t iterations) const
		{
			return derive_key(output_len, passphrase, &salt[0], salt.size(), iterations);
		}

		/**
		* Derive a key from a passphrase
		* @param output_len the desired length of the key to produce
		* @param passphrase the password to derive the key from
		* @param salt a randomly chosen salt
		* @param salt_len length of salt in bytes
		* @param msec is how long to run the PBKDF
		* @param iterations is set to the number of iterations used
		*/
		OctetString derive_key(size_t output_len,
									  in string passphrase,
									  in byte* salt, size_t salt_len,
									  std::chrono::milliseconds msec,
									  size_t& iterations) const;

		/**
		* Derive a key from a passphrase using a certain amount of time
		* @param output_len the desired length of the key to produce
		* @param passphrase the password to derive the key from
		* @param salt a randomly chosen salt
		* @param msec is how long to run the PBKDF
		* @param iterations is set to the number of iterations used
		*/
		OctetString derive_key(Alloc)(size_t output_len,
									  in string passphrase,
									  const Vector!( byte, Alloc )& salt,
									  std::chrono::milliseconds msec,
									  size_t& iterations) const
		{
			return derive_key(output_len, passphrase, &salt[0], salt.size(), msec, iterations);
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
		* @param msec if iterations is zero, then instead the PBKDF is
		*		  run until msec milliseconds has passed.
		* @return the number of iterations performed and the derived key
		*/
		abstract Pair!(size_t, OctetString)
			key_derivation(size_t output_len,
								in string passphrase,
								in byte* salt, size_t salt_len,
								size_t iterations,
								std::chrono::milliseconds msec) const;
};