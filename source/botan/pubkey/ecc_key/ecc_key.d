/*
* ECC Key implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*			 Falko Strenzke, FlexSecure GmbH
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ecc_key;
import botan.x509_key;
import botan.numthry;
import botan.der_enc;
import botan.ber_dec;
import botan.secmem;
import botan.point_gfp;
size_t EC_PublicKey::estimated_strength() const
{
	return domain().get_curve().get_p().bits() / 2;
}

EC_PublicKey::EC_PublicKey(in EC_Group dom_par,
									const PointGFp& pub_point) :
	domain_params(dom_par), public_key(pub_point),
	domain_encoding(EC_DOMPAR_ENC_EXPLICIT)
{
	if (domain().get_curve() != public_point().get_curve())
		throw new Invalid_Argument("EC_PublicKey: curve mismatch in constructor");
}

EC_PublicKey::EC_PublicKey(in AlgorithmIdentifier alg_id,
									in SafeVector!byte key_bits)
{
	domain_params = EC_Group(alg_id.parameters);
	domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

	public_key = OS2ECP(key_bits, domain().get_curve());
}

bool EC_PublicKey::check_key(RandomNumberGenerator,
									  bool) const
{
	return public_point().on_the_curve();
}

AlgorithmIdentifier EC_PublicKey::algorithm_identifier() const
{
	return AlgorithmIdentifier(get_oid(), DER_domain());
}

Vector!( byte ) EC_PublicKey::x509_subject_public_key() const
{
	return unlock(EC2OSP(public_point(), PointGFp::COMPRESSED));
}

void EC_PublicKey::set_parameter_encoding(EC_Group_Encoding form)
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

ref const BigInt EC_PrivateKey::private_value() const
{
	if (Private_Key == 0)
		throw new Invalid_State("EC_PrivateKey::private_value - uninitialized");

	return Private_Key;
}

/**
* EC_PrivateKey constructor
*/
EC_PrivateKey::EC_PrivateKey(RandomNumberGenerator rng,
									  const EC_Group& ec_group,
									  ref const BigInt x)
{
	domain_params = ec_group;
	domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

	if (x == 0)
		Private_Key = BigInt::random_integer(rng, 1, domain().get_order());
	else
		Private_Key = x;

	public_key = domain().get_base_point() * Private_Key;

	BOTAN_ASSERT(public_key.on_the_curve(),
					 "Generated public key point was on the curve");
}

SafeVector!byte EC_PrivateKey::pkcs8_Private_Key() const
{
	return DER_Encoder()
		.start_cons(SEQUENCE)
			.encode(cast(size_t)(1))
			.encode(BigInt::encode_1363(Private_Key, Private_Key.bytes()),
					  OCTET_STRING)
		.end_cons()
		.get_contents();
}

EC_PrivateKey::EC_PrivateKey(in AlgorithmIdentifier alg_id,
									  in SafeVector!byte key_bits)
{
	domain_params = EC_Group(alg_id.parameters);
	domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

	OID key_parameters;
	SafeVector!byte public_key_bits;

	BER_Decoder(key_bits)
		.start_cons(SEQUENCE)
			.decode_and_check<size_t>(1, "Unknown version code for ECC key")
			.decode_octet_string_bigint(Private_Key)
			.decode_optional(key_parameters, ASN1_Tag(0), PRIVATE)
			.decode_optional_string(public_key_bits, BIT_STRING, 1, PRIVATE)
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

}
