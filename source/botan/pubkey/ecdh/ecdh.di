/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.ecc_key;
import botan.pubkey.pk_ops;
/**
* This class represents ECDH Public Keys.
*/
class ECDH_PublicKey : EC_PublicKey
{
	public:

		ECDH_PublicKey(in AlgorithmIdentifier alg_id,
							in SafeVector!ubyte key_bits) :
			EC_PublicKey(alg_id, key_bits) {}

		/**
		* Construct a public key from a given public point.
		* @param dom_par the domain parameters associated with this key
		* @param public_point the public point defining this key
		*/
		ECDH_PublicKey(in EC_Group dom_par,
							const PointGFp& public_point) :
			EC_PublicKey(dom_par, public_point) {}

		/**
		* Get this keys algorithm name.
		* @return this keys algorithm name
		*/
		string algo_name() const { return "ECDH"; }

		/**
		* Get the maximum number of bits allowed to be fed to this key.
		* This is the bitlength of the order of the base point.

		* @return maximum number of input bits
		*/
		size_t max_input_bits() const { return domain().get_order().bits(); }

		/**
		* @return public point value
		*/
		Vector!ubyte public_value() const
		{ return unlock(EC2OSP(public_point(), PointGFp::UNCOMPRESSED)); }

	package:
		ECDH_PublicKey() {}
};

/**
* This class represents ECDH Private Keys.
*/
class ECDH_PrivateKey : ECDH_PublicKey,
											 public EC_PrivateKey,
											 public PK_Key_Agreement_Key
{
	public:

		ECDH_PrivateKey(in AlgorithmIdentifier alg_id,
							 in SafeVector!ubyte key_bits) :
			EC_PrivateKey(alg_id, key_bits) {}

		/**
		* Generate a new private key
		* @param rng a random number generator
		* @param domain parameters to used for this key
		* @param x the private key; if zero, a new random key is generated
		*/
		ECDH_PrivateKey(RandomNumberGenerator rng,
							 const EC_Group& domain,
							 ref const BigInt x = 0) :
			EC_PrivateKey(rng, domain, x) {}

		Vector!ubyte public_value() const
		{ return ECDH_PublicKey::public_value(); }
};

/**
* ECDH operation
*/
class ECDH_KA_Operation : pk_ops.Key_Agreement
{
	public:
		ECDH_KA_Operation(in ECDH_PrivateKey key);

		SafeVector!ubyte agree(in ubyte* w, size_t w_len);
	private:
		const CurveGFp& curve;
		ref const BigInt cofactor;
		BigInt l_times_priv;
};