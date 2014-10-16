/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.ec_group;
import botan.pk_keys;
import botan.x509_key;
import botan.pkcs8;
/**
* This class represents abstract ECC public keys. When encoding a key
* via an encoder that can be accessed via the corresponding member
* functions, the key will decide upon its internally stored encoding
* information whether to encode itself with or without domain
* parameters, or using the domain parameter oid. Furthermore, a public
* key without domain parameters can be decoded. In that case, it
* cannot be used for verification until its domain parameters are set
* by calling the corresponding member function.
*/
class EC_PublicKey : Public_Key
{
	public:
		EC_PublicKey(in EC_Group dom_par,
						 const ref PointGFp pub_point);

		EC_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!ubyte key_bits);

		/**
		* Get the public point of this key.
		* @throw new Invalid_State is thrown if the
		* domain parameters of this point are not set
		* @result the public point of this key
		*/
		const ref PointGFp public_point() const { return public_key; }

		AlgorithmIdentifier algorithm_identifier() const;

		Vector!ubyte x509_subject_public_key() const;

		bool check_key(RandomNumberGenerator rng,
							bool strong) const;

		/**
		* Get the domain parameters of this key.
		* @throw new Invalid_State is thrown if the
		* domain parameters of this point are not set
		* @result the domain parameters of this key
		*/
		const EC_Group& domain() const { return domain_params; }

		/**
		* Set the domain parameter encoding to be used when encoding this key.
		* @param enc the encoding to use
		*/
		void set_parameter_encoding(EC_Group_Encoding enc);

		/**
		* Return the DER encoding of this keys domain in whatever format
		* is preset for this particular key
		*/
		Vector!ubyte DER_domain() const
		{ return domain().DER_encode(domain_format()); }

		/**
		* Get the domain parameter encoding to be used when encoding this key.
		* @result the encoding to use
		*/
		EC_Group_Encoding domain_format() const
		{ return domain_encoding; }

		override size_t estimated_strength() const;

	package:
		EC_PublicKey() : domain_encoding(EC_DOMPAR_ENC_EXPLICIT) {}

		EC_Group domain_params;
		PointGFp public_key;
		EC_Group_Encoding domain_encoding;
};

/**
* This abstract class represents ECC private keys
*/
class EC_PrivateKey : EC_PublicKey,
										  public abstract Private_Key
{
	public:
	  EC_PrivateKey(RandomNumberGenerator rng,
						 const EC_Group& domain,
						 const ref BigInt Private_Key);

		EC_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits);

		SafeVector!ubyte pkcs8_Private_Key() const;

		/**
		* Get the private key value of this key object.
		* @result the private key value of this key object
		*/
		const ref BigInt private_value() const;
	package:
		EC_PrivateKey() {}

		BigInt Private_Key;
};