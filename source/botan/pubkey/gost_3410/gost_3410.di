/*
* GOST 34.10-2001
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.ecc_key;
import botan.pk_ops;
/**
* GOST-34.10 Public Key
*/
class GOST_3410_PublicKey : public abstract EC_PublicKey
{
	public:

		/**
		* Construct a public key from a given public point.
		* @param dom_par the domain parameters associated with this key
		* @param public_point the public point defining this key
		*/
		GOST_3410_PublicKey(in EC_Group dom_par,
								  const PointGFp& public_point) :
			EC_PublicKey(dom_par, public_point) {}

		/**
		* Construct from X.509 algorithm id and subject public key bits
		*/
		GOST_3410_PublicKey(in AlgorithmIdentifier alg_id,
								  in SafeVector!byte key_bits);

		/**
		* Get this keys algorithm name.
		* @result this keys algorithm name
		*/
		string algo_name() const { return "GOST-34.10"; }

		AlgorithmIdentifier algorithm_identifier() const;

		Vector!( byte ) x509_subject_public_key() const;

		/**
		* Get the maximum number of bits allowed to be fed to this key.
		* This is the bitlength of the order of the base point.

		* @result the maximum number of input bits
		*/
		size_t max_input_bits() const { return domain().get_order().bits(); }

		size_t message_parts() const { return 2; }

		size_t message_part_size() const
		{ return domain().get_order().bytes(); }

	protected:
		GOST_3410_PublicKey() {}
};

/**
* GOST-34.10 Private Key
*/
class GOST_3410_PrivateKey : public GOST_3410_PublicKey,
													public EC_PrivateKey
{
	public:

		GOST_3410_PrivateKey(in AlgorithmIdentifier alg_id,
									in SafeVector!byte key_bits) :
			EC_PrivateKey(alg_id, key_bits) {}

		/**
		* Generate a new private key
		* @param rng a random number generator
		* @param domain parameters to used for this key
		* @param x the private key; if zero, a new random key is generated
		*/
		GOST_3410_PrivateKey(RandomNumberGenerator& rng,
									const EC_Group& domain,
									ref const BigInt x = 0) :
			EC_PrivateKey(rng, domain, x) {}

		AlgorithmIdentifier pkcs8_algorithm_identifier() const
		{ return EC_PublicKey::algorithm_identifier(); }
};

/**
* GOST-34.10 signature operation
*/
class GOST_3410_Signature_Operation : public PK_Ops::Signature
{
	public:
		GOST_3410_Signature_Operation(in GOST_3410_PrivateKey gost_3410);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return order.bytes(); }
		size_t max_input_bits() const { return order.bits(); }

		SafeVector!byte sign(in byte* msg, size_t msg_len,
										RandomNumberGenerator& rng);

	private:
		const PointGFp& base_point;
		ref const BigInt order;
		ref const BigInt x;
};

/**
* GOST-34.10 verification operation
*/
class GOST_3410_Verification_Operation : public PK_Ops::Verification
{
	public:
		GOST_3410_Verification_Operation(in GOST_3410_PublicKey gost);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return order.bytes(); }
		size_t max_input_bits() const { return order.bits(); }

		bool with_recovery() const { return false; }

		bool verify(in byte* msg, size_t msg_len,
						in byte* sig, size_t sig_len);
	private:
		const PointGFp& base_point;
		const PointGFp& public_point;
		ref const BigInt order;
};