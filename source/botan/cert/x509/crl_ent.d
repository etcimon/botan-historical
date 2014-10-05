/*
* CRL Entry
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.crl_ent;
import botan.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.bigint;
import botan.asn1.oid_lookup.oids;
/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(bool t_on_unknown_crit) :
	throw_on_unknown_critical(t_on_unknown_crit)
{
	reason = UNSPECIFIED;
}

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(in X509_Certificate cert, CRL_Code why) :
	throw_on_unknown_critical(false)
{
	serial = cert.serial_number();
	time = X509_Time(std::chrono::system_clock::now());
	reason = why;
}

/*
* Compare two CRL_Entrys for equality
*/
bool operator==(in CRL_Entry a1, const CRL_Entry& a2)
{
	if (a1.serial_number() != a2.serial_number())
		return false;
	if (a1.expire_time() != a2.expire_time())
		return false;
	if (a1.reason_code() != a2.reason_code())
		return false;
	return true;
}

/*
* Compare two CRL_Entrys for inequality
*/
bool operator!=(in CRL_Entry a1, const CRL_Entry& a2)
{
	return !(a1 == a2);
}

/*
* DER encode a CRL_Entry
*/
void CRL_Entry::encode_into(DER_Encoder& der) const
{
	Extensions extensions;

	extensions.add(new Cert_Extension::CRL_ReasonCode(reason));

	der.start_cons(ASN1_Tag.SEQUENCE)
		.encode(BigInt::decode(serial))
			.encode(time)
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(extensions)
			 .end_cons()
		.end_cons();
}

/*
* Decode a BER encoded CRL_Entry
*/
void CRL_Entry::decode_from(BER_Decoder& source)
{
	BigInt serial_number_bn;
	reason = UNSPECIFIED;

	BER_Decoder entry = source.start_cons(ASN1_Tag.SEQUENCE);

	entry.decode(serial_number_bn).decode(time);

	if (entry.more_items())
	{
		Extensions extensions(throw_on_unknown_critical);
		entry.decode(extensions);
		Data_Store info;
		extensions.contents_to(info, info);
		reason = CRL_Code(info.get1_uint("X509v3.CRLReasonCode"));
	}

	entry.end_cons();

	serial = BigInt::encode(serial_number_bn);
}

}
