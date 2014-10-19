/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.math.bigint.bigint;
import botan.x509_key;
import botan.pubkey.pkcs8;
/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IF_Scheme_PublicKey : Public_Key
{
	public:
		IF_Scheme_PublicKey(in AlgorithmIdentifier alg_id,
								  in SafeVector!ubyte key_bits);

		IF_Scheme_PublicKey(in BigInt n, const ref BigInt e) :
			n(n), e(e) {}

		bool check_key(RandomNumberGenerator rng, bool) const;

		AlgorithmIdentifier algorithm_identifier() const;

		Vector!ubyte x509_subject_public_key() const;

		/**
		* @return public modulus
		*/
		const ref BigInt get_n() const { return n; }

		/**
		* @return public exponent
		*/
		const ref BigInt get_e() const { return e; }

		size_t max_input_bits() const { return (n.bits() - 1); }

		override size_t estimated_strength() const;

	package:
		IF_Scheme_PublicKey() {}

		BigInt n, e;
};

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IF_Scheme_PrivateKey : IF_Scheme_PublicKey,
													public abstract Private_Key
{
	public:

		IF_Scheme_PrivateKey(RandomNumberGenerator rng,
									const ref BigInt prime1, const ref BigInt prime2,
									const ref BigInt exp, const ref BigInt d_exp,
									const ref BigInt mod);

		IF_Scheme_PrivateKey(RandomNumberGenerator rng,
									const AlgorithmIdentifier alg_id,
									in SafeVector!ubyte key_bits);

		bool check_key(RandomNumberGenerator rng, bool) const;

		/**
		* Get the first prime p.
		* @return prime p
		*/
		const ref BigInt get_p() const { return p; }

		/**
		* Get the second prime q.
		* @return prime q
		*/
		const ref BigInt get_q() const { return q; }

		/**
		* Get d with exp * d = 1 mod (p - 1, q - 1).
		* @return d
		*/
		const ref BigInt get_d() const { return d; }

		const ref BigInt get_c() const { return c; }
		const ref BigInt get_d1() const { return d1; }
		const ref BigInt get_d2() const { return d2; }

		SafeVector!ubyte pkcs8_Private_Key() const;

	package:
		IF_Scheme_PrivateKey() {}

		BigInt d, p, q, d1, d2, c;
};