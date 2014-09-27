/*
* Discrete Logarithm Group
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.data_src;
/**
* This class represents discrete logarithm groups. It holds a prime p,
* a prime q = (p-1)/2 and g = x^((p-1)/q) mod p.
*/
class DL_Group
{
	public:

		/**
		* Get the prime p.
		* @return prime p
		*/
		ref const BigInt get_p() const;

		/**
		* Get the prime q.
		* @return prime q
		*/
		ref const BigInt get_q() const;

		/**
		* Get the base g.
		* @return base g
		*/
		ref const BigInt get_g() const;

		/**
		* The DL group encoding format variants.
		*/
		enum Format {
			ANSI_X9_42,
			ANSI_X9_57,
			PKCS_3,

			DSA_PARAMETERS = ANSI_X9_57,
			DH_PARAMETERS = ANSI_X9_42,
			X942_DH_PARAMETERS = ANSI_X9_42,
			PKCS3_DH_PARAMETERS = PKCS_3
	};

		/**
		* Determine the prime creation for DL groups.
		*/
		enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

		/**
		* Perform validity checks on the group.
		* @param rng the rng to use
		* @param strong whether to perform stronger by lengthier tests
		* @return true if the object is consistent, false otherwise
		*/
		bool verify_group(RandomNumberGenerator& rng, bool strong) const;

		/**
		* Encode this group into a string using PEM encoding.
		* @param format the encoding format
		* @return string holding the PEM encoded group
		*/
		string PEM_encode(Format format) const;

		/**
		* Encode this group into a string using DER encoding.
		* @param format the encoding format
		* @return string holding the DER encoded group
		*/
		Vector!( byte ) DER_encode(Format format) const;

		/**
		* Decode a DER/BER encoded group into this instance.
		* @param ber a vector containing the DER/BER encoded group
		* @param format the format of the encoded group
		*/
		void BER_decode(in Vector!byte ber,
							 Format format);

		/**
		* Decode a PEM encoded group into this instance.
		* @param pem the PEM encoding of the group
		*/
		void PEM_decode(in string pem);

		/**
		* Construct a DL group with uninitialized internal value.
		* Use this constructor is you wish to set the groups values
		* from a DER or PEM encoded group.
		*/
		DL_Group();

		/**
		* Construct a DL group that is registered in the configuration.
		* @param name the name that is configured in the global configuration
		* for the desired group. If no configuration file is specified,
		* the default values from the file policy.cpp will be used. For instance,
		* use "modp/ietf/768" as name.
		*/
		DL_Group(in string name);

		/**
		* Create a new group randomly.
		* @param rng the random number generator to use
		* @param type specifies how the creation of primes p and q shall
		* be performed. If type=Strong, then p will be determined as a
		* safe prime, and q will be chosen as (p-1)/2. If
		* type=Prime_Subgroup and qbits = 0, then the size of q will be
		* determined according to the estimated difficulty of the DL
		* problem. If type=DSA_Kosherizer, DSA primes will be created.
		* @param pbits the number of bits of p
		* @param qbits the number of bits of q. Leave it as 0 to have
		* the value determined according to pbits.
		*/
		DL_Group(RandomNumberGenerator& rng, PrimeType type,
					size_t pbits, size_t qbits = 0);

		/**
		* Create a DSA group with a given seed.
		* @param rng the random number generator to use
		* @param seed the seed to use to create the random primes
		* @param pbits the desired bit size of the prime p
		* @param qbits the desired bit size of the prime q.
		*/
		DL_Group(RandomNumberGenerator& rng,
					in Vector!byte seed,
					size_t pbits = 1024, size_t qbits = 0);

		/**
		* Create a DL group. The prime q will be determined according to p.
		* @param p the prime p
		* @param g the base g
		*/
		DL_Group(in BigInt p, ref const BigInt g);

		/**
		* Create a DL group.
		* @param p the prime p
		* @param q the prime q
		* @param g the base g
		*/
		DL_Group(in BigInt p, ref const BigInt q, ref const BigInt g);

		/**
		* Return PEM representation of named DL group
		*/
		static string PEM_for_named_group(in string name);
	private:
		static BigInt make_dsa_generator(in BigInt, ref const BigInt);

		void init_check() const;
		void initialize(in BigInt, ref const BigInt, ref const BigInt);
		bool initialized;
		BigInt p, q, g;
};