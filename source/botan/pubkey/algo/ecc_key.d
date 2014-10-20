/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecc_key;

import botan.pubkey.algo.ec_group;
import botan.pubkey.pk_keys;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.alloc.secmem;
import botan.math.ec_gfp.curve_gfp;

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
	this(in EC_Group dom_par,
	     const ref PointGFp pub_point) 
	{
		domain_params = dom_par;
		public_key = pub_point;
		domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		if (domain().get_curve() != public_point().get_curve())
			throw new Invalid_Argument("EC_PublicKey: curve mismatch in constructor");
	}

	this(in AlgorithmIdentifier alg_id,
	     in SafeVector!ubyte key_bits)
	{
		domain_params = EC_Group(alg_id.parameters);
		domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		public_key = OS2ECP(key_bits, domain().get_curve());
	}

	/**
	* Get the public point of this key.
	* @throw new Invalid_State is thrown if the
	* domain parameters of this point are not set
	* @result the public point of this key
	*/
	const ref PointGFp public_point() const { return public_key; }

	AlgorithmIdentifier algorithm_identifier() const
	{
		return AlgorithmIdentifier(get_oid(), DER_domain());
	}

	Vector!ubyte x509_subject_public_key() const
	{
		return unlock(EC2OSP(public_point(), PointGFp.COMPRESSED));
	}

	bool check_key(RandomNumberGenerator,
	               bool) const
	{
		return public_point().on_the_curve();
	}

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
	void set_parameter_encoding(EC_Group_Encoding form)
	{
		if (form != EC_DOMPAR_ENC_EXPLICIT &&
		    form != EC_DOMPAR_ENC_IMPLICITCA &&
		    form != EC_DOMPAR_ENC_OID)
			throw new Invalid_Argument("Invalid encoding form for EC-key object specified");
		
		if ((form == EC_DOMPAR_ENC_OID) && (domain_params.get_oid() == ""))
			throw new Invalid_Argument("Invalid encoding form OID specified for "
			                           "EC-key object whose corresponding domain "
			                           "parameters are without oid");
		
		domain_encoding = form;
	}

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

	override size_t estimated_strength() const
	{
		return domain().get_curve().get_p().bits() / 2;
	}


package:
	this() 
	{
		domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
	}

	EC_Group domain_params;
	PointGFp public_key;
	EC_Group_Encoding domain_encoding;
};

/**
* This abstract class represents ECC private keys
*/
class EC_PrivateKey : EC_PublicKey,
						Private_Key
{
public:
	/**
	* EC_PrivateKey constructor
	*/
	this(RandomNumberGenerator rng,
	     const ref EC_Group ec_group,
	     const ref BigInt private_key)
	{
		domain_params = ec_group;
		domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		if (private_key == 0)
			Private_Key = BigInt.random_integer(rng, 1, domain().get_order());
		else
			Private_Key = private_key;
		
		public_key = domain().get_base_point() * Private_Key;
		
		BOTAN_ASSERT(public_key.on_the_curve(),
		             "Generated public key point was on the curve");
	}

	this(in AlgorithmIdentifier alg_id,
	     in SafeVector!ubyte key_bits)
	{
		domain_params = EC_Group(alg_id.parameters);
		domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		OID key_parameters;
		SafeVector!ubyte public_key_bits;
		
		BER_Decoder(key_bits)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check<size_t>(1, "Unknown version code for ECC key")
				.decode_octet_string_bigint(Private_Key)
				.decode_optional(key_parameters, ASN1_Tag(0), PRIVATE)
				.decode_optional_string(public_key_bits, ASN1_Tag.BIT_STRING, 1, PRIVATE)
				.end_cons();
		
		if (!key_parameters.empty() && key_parameters != alg_id.oid)
			throw new Decoding_Error("EC_PrivateKey - inner and outer OIDs did not match");
		
		if (public_key_bits.empty())
		{
			public_key = domain().get_base_point() * Private_Key;
			
			BOTAN_ASSERT(public_key.on_the_curve(),
			             "Public point derived from loaded key was on the curve");
		}
		else
		{
			public_key = OS2ECP(public_key_bits, domain().get_curve());
			// OS2ECP verifies that the point is on the curve
		}
	}

	SafeVector!ubyte pkcs8_Private_Key() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(cast(size_t)(1))
				.encode(BigInt.encode_1363(Private_Key, Private_Key.bytes()),
				        ASN1_Tag.OCTET_STRING)
				.end_cons()
				.get_contents();
	}

	/**
	* Get the private key value of this key object.
	* @result the private key value of this key object
	*/
	const ref BigInt private_value() const
	{
		if (Private_Key == 0)
			throw new Invalid_State("EC_PrivateKey::private_value - uninitialized");
		
		return Private_Key;
	}
package:
	this() {}

	BigInt Private_Key;
};