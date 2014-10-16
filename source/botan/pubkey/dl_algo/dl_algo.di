/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.dl_group;
import botan.x509_key;
import botan.pkcs8;
/**
* This class represents discrete logarithm (DL) public keys.
*/
class DL_Scheme_PublicKey : Public_Key
{
	public:
		bool check_key(RandomNumberGenerator rng, bool) const;

		AlgorithmIdentifier algorithm_identifier() const;

		Vector!ubyte x509_subject_public_key() const;

		/**
		* Get the DL domain parameters of this key.
		* @return DL domain parameters of this key
		*/
		const DL_Group& get_domain() const { return group; }

		/**
		* Get the public value y with y = g^x mod p where x is the secret key.
		*/
		const ref BigInt get_y() const { return y; }

		/**
		* Get the prime p of the underlying DL group.
		* @return prime p
		*/
		const ref BigInt group_p() const { return group.get_p(); }

		/**
		* Get the prime q of the underlying DL group.
		* @return prime q
		*/
		const ref BigInt group_q() const { return group.get_q(); }

		/**
		* Get the generator g of the underlying DL group.
		* @return generator g
		*/
		const ref BigInt group_g() const { return group.get_g(); }

		/**
		* Get the underlying groups encoding format.
		* @return encoding format
		*/
		abstract DL_Group::Format group_format() const;

		override size_t estimated_strength() const;

		DL_Scheme_PublicKey(in AlgorithmIdentifier alg_id,
								  in SafeVector!ubyte key_bits,
								  DL_Group::Format group_format);

	package:
		DL_Scheme_PublicKey() {}

		/**
		* The DL public key
		*/
		BigInt y;

		/**
		* The DL group
		*/
		DL_Group group;
};

/**
* This class represents discrete logarithm (DL) private keys.
*/
class DL_Scheme_PrivateKey : DL_Scheme_PublicKey,
													public abstract Private_Key
{
	public:
		bool check_key(RandomNumberGenerator rng, bool) const;

		/**
		* Get the secret key x.
		* @return secret key
		*/
		const ref BigInt get_x() const { return x; }

		SafeVector!ubyte pkcs8_Private_Key() const;

		DL_Scheme_PrivateKey(in AlgorithmIdentifier alg_id,
									in SafeVector!ubyte key_bits,
									DL_Group::Format group_format);

	package:
		DL_Scheme_PrivateKey() {}

		/**
		* The DL private key
		*/
		BigInt x;
};