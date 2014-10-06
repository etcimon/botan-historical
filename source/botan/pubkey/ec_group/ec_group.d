/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*	  2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ec_group;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.libstate;
import botan.asn1.oid_lookup.oids;
import botan.codec.pem.pem;
EC_Group::EC_Group(in OID domain_oid)
{
	string pem = PEM_for_named_group(oids.lookup(domain_oid));

	if (!pem)
		throw new Lookup_Error("No ECC domain data for " ~ domain_oid.as_string());

	*this = EC_Group(pem);
	oid = domain_oid.as_string();
}

EC_Group::EC_Group(in string str)
{
	if (str == "")
		return; // no initialization / uninitialized

	try
	{
		Vector!ubyte ber =
			unlock(pem.decode_check_label(str, "EC PARAMETERS"));

		*this = EC_Group(ber);
	}
	catch(Decoding_Error) // hmm, not PEM?
	{
		*this = EC_Group(oids.lookup(str));
	}
}

EC_Group::EC_Group(in Vector!ubyte ber_data)
{
	BER_Decoder ber(ber_data);
	BER_Object obj = ber.get_next_object();

	if (obj.type_tag == ASN1_Tag.NULL_TAG)
		throw new Decoding_Error("Cannot handle ImplicitCA ECDSA parameters");
	else if (obj.type_tag == ASN1_Tag.OBJECT_ID)
	{
		OID dom_par_oid;
		BER_Decoder(ber_data).decode(dom_par_oid);
		*this = EC_Group(dom_par_oid);
	}
	else if (obj.type_tag == ASN1_Tag.SEQUENCE)
	{
		BigInt p, a, b;
		Vector!ubyte sv_base_point;

		BER_Decoder(ber_data)
			.start_cons(ASN1_Tag.SEQUENCE)
			  .decode_and_check<size_t>(1, "Unknown ECC param version code")
			  .start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check(OID("1.2.840.10045.1.1"),
										"Only prime ECC fields supported")
				 .decode(p)
			  .end_cons()
			  .start_cons(ASN1_Tag.SEQUENCE)
				 .decode_octet_string_bigint(a)
				 .decode_octet_string_bigint(b)
			  .end_cons()
			  .decode(sv_base_point, ASN1_Tag.OCTET_STRING)
			  .decode(order)
			  .decode(cofactor)
			.end_cons()
			.verify_end();

		curve = CurveGFp(p, a, b);
		base_point = OS2ECP(sv_base_point, curve);
	}
	else
		throw new Decoding_Error("Unexpected tag while decoding ECC domain params");
}

Vector!ubyte
EC_Group::DER_encode(EC_Group_Encoding form) const
{
	if (form == EC_DOMPAR_ENC_EXPLICIT)
	{
		const size_t ecpVers1 = 1;
		OID curve_type("1.2.840.10045.1.1");

		const size_t p_bytes = curve.get_p().bytes();

		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(ecpVers1)
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(curve_type)
					.encode(curve.get_p())
				.end_cons()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(BigInt::encode_1363(curve.get_a(), p_bytes),
							  ASN1_Tag.OCTET_STRING)
					.encode(BigInt::encode_1363(curve.get_b(), p_bytes),
							  ASN1_Tag.OCTET_STRING)
				.end_cons()
				.encode(EC2OSP(base_point, PointGFp::UNCOMPRESSED), ASN1_Tag.OCTET_STRING)
				.encode(order)
				.encode(cofactor)
			.end_cons()
			.get_contents_unlocked();
	}
	else if (form == EC_DOMPAR_ENC_OID)
		return DER_Encoder().encode(OID(get_oid())).get_contents_unlocked();
	else if (form == EC_DOMPAR_ENC_IMPLICITCA)
		return DER_Encoder().encode_null().get_contents_unlocked();
	else
		throw new Internal_Error("EC_Group::DER_encode: Unknown encoding");
}

string EC_Group::PEM_encode() const
{
	const Vector!ubyte der = DER_encode(EC_DOMPAR_ENC_EXPLICIT);
	return pem.encode(der, "EC PARAMETERS");
}

}
