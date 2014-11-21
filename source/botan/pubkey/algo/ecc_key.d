/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecc_key;

import botan.constants;
static if (BOTAN_HAS_ECDH || BOTAN_HAS_ECDSA || BOTAN_HAS_GOST_34_10_2001):

public import botan.math.ec_gfp.ec_group;
public import botan.math.numbertheory.numthry;
public import botan.math.ec_gfp.curve_gfp;
public import botan.math.ec_gfp.point_gfp;
public import botan.pubkey.pk_keys;
public import botan.pubkey.x509_key;
import botan.rng.rng;
import botan.pubkey.pkcs8;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.memory.zeroize;
import botan.utils.exceptn;

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
	this(in EC_Group dom_par, in PointGFp pub_point) 
	{
		m_domain_params = dom_par;
		m_public_key = pub_point;
		m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		if (domain().get_curve() != public_point().get_curve())
			throw new Invalid_Argument("EC_PublicKey: curve mismatch in constructor");
	}

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits)
	{
		m_domain_params = EC_Group(alg_id.parameters);
		m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		m_public_key = OS2ECP(key_bits, domain().get_curve());
	}

	/**
	* Get the public point of this key.
	* @throw new Invalid_State is thrown if the
	* domain parameters of this point are not set
	* @result the public point of this key
	*/
	const ref PointGFp public_point() const { return m_public_key; }

	Algorithm_Identifier algorithm_identifier() const
	{
		return Algorithm_Identifier(get_oid(), DER_domain());
	}

	Vector!ubyte x509_subject_public_key() const
	{
		return unlock(EC2OSP(public_point(), PointGFp.COMPRESSED));
	}

	bool check_key(RandomNumberGenerator, bool) const
	{
		return public_point().on_the_curve();
	}

	/**
	* Get the domain parameters of this key.
	* @throw new Invalid_State is thrown if the
	* domain parameters of this point are not set
	* @result the domain parameters of this key
	*/
	const EC_Group domain() const { return m_domain_params; }

	/**
	* Set the domain parameter encoding to be used when encoding this key.
	* @param enc the encoding to use
	*/
	void set_parameter_encoding(EC_Group_Encoding form)
	{
		if (form != EC_DOMPAR_ENC_EXPLICIT && form != EC_DOMPAR_ENC_IMPLICITCA && form != EC_DOMPAR_ENC_OID)
			throw new Invalid_Argument("Invalid encoding form for EC-key object specified");
		
		if ((form == EC_DOMPAR_ENC_OID) && (m_domain_params.get_oid() == ""))
			throw new Invalid_Argument("Invalid encoding form OID specified for "
			                           "EC-key object whose corresponding domain "
			                           "parameters are without oid");
		
		m_domain_encoding = form;
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
	{ return m_domain_encoding; }

	override size_t estimated_strength() const
	{
		return domain().get_curve().get_p().bits() / 2;
	}


protected:
	this() 
	{		m_public_key = pub_point;
		
		m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
	}

	EC_Group m_domain_params;
	PointGFp m_public_key;
	EC_Group_Encoding m_domain_encoding;
}

/**
* This abstract class represents ECC private keys
*/
final class EC_PrivateKey : EC_PublicKey,
							Private_Key
{
public:
	/**
	* EC_PrivateKey constructor
	*/
	this(RandomNumberGenerator rng, in EC_Group ec_group, in BigInt private_key)
	{
		m_domain_params = ec_group;
		m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		if (private_key == 0)
			m_private_key = BigInt.random_integer(rng, 1, domain().get_order());
		else
			m_private_key = private_key;
		
		m_public_key = domain().get_base_point() * m_private_key;
		
		assert(m_public_key.on_the_curve(), "Generated public key point was on the curve");
	}

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits)
	{
		m_domain_params = EC_Group(alg_id.parameters);
		m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
		
		OID key_parameters;
		Secure_Vector!ubyte public_key_bits;
		
		BER_Decoder(key_bits)
				.start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check!size_t(1, "Unknown version code for ECC key")
				.decode_octet_string_bigint(m_private_key)
				.decode_optional(key_parameters, ASN1_Tag(0), ASN1_Tag.PRIVATE)
				.decode_optional_string(public_key_bits, ASN1_Tag.BIT_STRING, 1, ASN1_Tag.PRIVATE)
				.end_cons();
		
		if (!key_parameters.empty && key_parameters != alg_id.oid)
			throw new Decoding_Error("EC_PrivateKey - inner and outer OIDs did not match");
		
		if (public_key_bits.empty)
		{
			m_public_key = domain().get_base_point() * m_private_key;
			
			assert(m_public_key.on_the_curve(), "Public point derived from loaded key was on the curve");
		}
		else
		{
			public_key = OS2ECP(public_key_bits, domain().get_curve());
			// OS2ECP verifies that the point is on the curve
		}
	}

	Secure_Vector!ubyte pkcs8_private_key() const
	{
		return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(cast(size_t)(1))
				.encode(BigInt.encode_1363(m_private_key, m_private_key.bytes()),
				        ASN1_Tag.OCTET_STRING)
				.end_cons()
				.get_contents();
	}

	/**
	* Get the private key value of this key object.
	* @result the private key value of this key object
	*/
	const BigInt private_value() const
	{
		if (m_private_key == 0)
			throw new Invalid_State("EC_PrivateKey::private_value - uninitialized");
		
		return m_private_key;
	}
protected:
	this() {}

	BigInt m_private_key;
}