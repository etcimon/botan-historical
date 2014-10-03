/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.x509_key;
import botan.pkcs8;
/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IF_Scheme_PublicKey : public abstract Public_Key
{
	public:
		IF_Scheme_PublicKey(in AlgorithmIdentifier alg_id,
								  in SafeVector!byte key_bits);

		IF_Scheme_PublicKey(in BigInt n, ref const BigInt e) :
			n(n), e(e) {}

		bool check_key(RandomNumberGenerator rng, bool) const;

		AlgorithmIdentifier algorithm_identifier() const;

		Vector!( byte ) x509_subject_public_key() const;

		/**
		* @return public modulus
		*/
		ref const BigInt get_n() const { return n; }

		/**
		* @return public exponent
		*/
		ref const BigInt get_e() const { return e; }

		size_t max_input_bits() const { return (n.bits() - 1); }

		size_t estimated_strength() const override;

	package:
		IF_Scheme_PublicKey() {}

		BigInt n, e;
};

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IF_Scheme_PrivateKey : public abstract IF_Scheme_PublicKey,
													public abstract Private_Key
{
	public:

		IF_Scheme_PrivateKey(RandomNumberGenerator rng,
									ref const BigInt prime1, ref const BigInt prime2,
									ref const BigInt exp, ref const BigInt d_exp,
									ref const BigInt mod);

		IF_Scheme_PrivateKey(RandomNumberGenerator rng,
									const AlgorithmIdentifier& alg_id,
									in SafeVector!byte key_bits);

		bool check_key(RandomNumberGenerator rng, bool) const;

		/**
		* Get the first prime p.
		* @return prime p
		*/
		ref const BigInt get_p() const { return p; }

		/**
		* Get the second prime q.
		* @return prime q
		*/
		ref const BigInt get_q() const { return q; }

		/**
		* Get d with exp * d = 1 mod (p - 1, q - 1).
		* @return d
		*/
		ref const BigInt get_d() const { return d; }

		ref const BigInt get_c() const { return c; }
		ref const BigInt get_d1() const { return d1; }
		ref const BigInt get_d2() const { return d2; }

		SafeVector!byte pkcs8_Private_Key() const;

	package:
		IF_Scheme_PrivateKey() {}

		BigInt d, p, q, d1, d2, c;
};