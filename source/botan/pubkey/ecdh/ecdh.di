/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/ecc_key.h>
#include <botan/pk_ops.h>
/**
* This class represents ECDH Public Keys.
*/
class ECDH_PublicKey : public abstract EC_PublicKey
{
	public:

		ECDH_PublicKey(in AlgorithmIdentifier alg_id,
							in SafeVector!byte key_bits) :
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
		Vector!( byte ) public_value() const
		{ return unlock(EC2OSP(public_point(), PointGFp::UNCOMPRESSED)); }

	protected:
		ECDH_PublicKey() {}
};

/**
* This class represents ECDH Private Keys.
*/
class ECDH_PrivateKey : public ECDH_PublicKey,
											 public EC_PrivateKey,
											 public PK_Key_Agreement_Key
{
	public:

		ECDH_PrivateKey(in AlgorithmIdentifier alg_id,
							 in SafeVector!byte key_bits) :
			EC_PrivateKey(alg_id, key_bits) {}

		/**
		* Generate a new private key
		* @param rng a random number generator
		* @param domain parameters to used for this key
		* @param x the private key; if zero, a new random key is generated
		*/
		ECDH_PrivateKey(RandomNumberGenerator& rng,
							 const EC_Group& domain,
							 const BigInt& x = 0) :
			EC_PrivateKey(rng, domain, x) {}

		Vector!( byte ) public_value() const
		{ return ECDH_PublicKey::public_value(); }
};

/**
* ECDH operation
*/
class ECDH_KA_Operation : public PK_Ops::Key_Agreement
{
	public:
		ECDH_KA_Operation(in ECDH_PrivateKey key);

		SafeVector!byte agree(in byte[] w, size_t w_len);
	private:
		const CurveGFp& curve;
		const BigInt& cofactor;
		BigInt l_times_priv;
};