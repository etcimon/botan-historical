/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.hash;
import botan.rng;
import botan.algo_base.symkey;
import string;
/**
* SRP6a Client side
* @param username the username we are attempting login for
* @param password the password we are attempting to use
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param salt is the salt value sent by the server
* @param B is the server's public value
* @param rng is a random number generator
*
* @return (A,K) the client public key and the shared secret key
*/
std::pair<BigInt,SymmetricKey>
srp6_client_agree(in string username,
									 in string password,
									 in string group_id,
									 in string hash_id,
									 in Vector!ubyte salt,
									 ref const BigInt B,
									 RandomNumberGenerator rng);

/**
* Generate a new SRP-6 verifier
* @param identifier a username or other client identifier
* @param password the secret used to authenticate user
* @param salt a randomly chosen value, at least 128 bits long
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
*/
BigInt generate_srp6_verifier(in string identifier,
													 in string password,
													 in Vector!ubyte salt,
													 in string group_id,
													 in string hash_id);

/**
* Return the group id for this SRP param set, or else thrown an
* exception
* @param N the group modulus
* @param g the group generator
* @return group identifier
*/
string srp6_group_identifier(in BigInt N, ref const BigInt g);

/**
* Represents a SRP-6a server session
*/
class SRP6_Server_Session
{
	public:
		/**
		* Server side step 1
		* @param v the verification value saved from client registration
		* @param group_id the SRP group id
		* @param hash_id the SRP hash in use
		* @param rng a random number generator
		* @return SRP-6 B value
		*/
		BigInt step1(in BigInt v,
						 in string group_id,
						 in string hash_id,
						 RandomNumberGenerator rng);

		/**
		* Server side step 2
		* @param A the client's value
		* @return shared symmetric key
		*/
		SymmetricKey step2(in BigInt A);

	private:
		string hash_id;
		BigInt B, b, v, S, p;
		size_t p_bytes;
};