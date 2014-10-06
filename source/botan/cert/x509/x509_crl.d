/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509_crl;
import botan.x509_ext;
import botan.x509cert;
import botan.asn1.ber_dec;
import botan.parsing;
import botan.bigint;
import botan.asn1.oid_lookup.oids;
/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(DataSource& in, bool touc) :
	X509_Object(input, "X509 CRL/CRL"), throw_on_unknown_critical(touc)
{
	do_decode();
}

/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(in string in, bool touc) :
	X509_Object(input, "CRL/X509 CRL"), throw_on_unknown_critical(touc)
{
	do_decode();
}

X509_CRL::X509_CRL(in Vector!ubyte in, bool touc) :
	X509_Object(input, "CRL/X509 CRL"), throw_on_unknown_critical(touc)
{
	do_decode();
}

/**
* Check if this particular certificate is listed in the CRL
*/
bool X509_CRL::is_revoked(in X509_Certificate cert) const
{
	/*
	If the cert wasn't issued by the CRL issuer, it's possible the cert
	is revoked, but not by this CRL. Maybe throw new an exception instead?
	*/
	if (cert.issuer_dn() != issuer_dn())
		return false;

	Vector!ubyte crl_akid = authority_key_id();
	Vector!ubyte cert_akid = cert.authority_key_id();

	if (!crl_akid.empty() && !cert_akid.empty())
		if (crl_akid != cert_akid)
			return false;

	Vector!ubyte cert_serial = cert.serial_number();

	bool is_revoked = false;

	for (size_t i = 0; i != revoked.size(); ++i)
	{
		if (cert_serial == revoked[i].serial_number())
		{
			if (revoked[i].reason_code() == CRL_Code.REMOVE_FROM_CRL)
				is_revoked = false;
			else
				is_revoked = true;
		}
	}

	return is_revoked;
}

/*
* Decode the TBSCertList data
*/
void X509_CRL::force_decode()
{
	BER_Decoder tbs_crl(tbs_bits);

	size_t _version;
	tbs_crl.decode_optional(_version, INTEGER, ASN1_Tag.UNIVERSAL);

	if (_version != 0 && _version != 1)
		throw new X509_CRL_Error("Unknown X.509 CRL version " ~
									std.conv.to!string(_version+1));

	AlgorithmIdentifier sig_algo_inner;
	tbs_crl.decode(sig_algo_inner);

	if (sig_algo != sig_algo_inner)
		throw new X509_CRL_Error("Algorithm identifier mismatch");

	X509_DN dn_issuer;
	tbs_crl.decode(dn_issuer);
	info.add(dn_issuer.contents());

	X509_Time start, end;
	tbs_crl.decode(start).decode(end);
	info.add("X509.CRL.start", start.readable_string());
	info.add("X509.CRL.end", end.readable_string());

	BER_Object next = tbs_crl.get_next_object();

	if (next.type_tag == ASN1_Tag.SEQUENCE && next.class_tag == CONSTRUCTED)
	{
		BER_Decoder cert_list(next.value);

		while(cert_list.more_items())
		{
			CRL_Entry entry(throw_on_unknown_critical);
			cert_list.decode(entry);
			revoked.push_back(entry);
		}
		next = tbs_crl.get_next_object();
	}

	if (next.type_tag == 0 &&
		next.class_tag == ASN1_Tag(CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC))
	{
		BER_Decoder crl_options(next.value);

		Extensions extensions(throw_on_unknown_critical);

		crl_options.decode(extensions).verify_end();

		extensions.contents_to(info, info);

		next = tbs_crl.get_next_object();
	}

	if (next.type_tag != ASN1_Tag.NO_OBJECT)
		throw new X509_CRL_Error("Unknown tag in CRL");

	tbs_crl.verify_end();
}

/*
* Return the list of revoked certificates
*/
Vector!( CRL_Entry ) X509_CRL::get_revoked() const
{
	return revoked;
}

/*
* Return the distinguished name of the issuer
*/
X509_DN X509_CRL::issuer_dn() const
{
	return create_dn(info);
}

/*
* Return the key identifier of the issuer
*/
Vector!ubyte X509_CRL::authority_key_id() const
{
	return info.get1_memvec("X509v3.AuthorityKeyIdentifier");
}

/*
* Return the CRL number of this CRL
*/
uint X509_CRL::crl_number() const
{
	return info.get1_uint("X509v3.CRLNumber");
}

/*
* Return the issue data of the CRL
*/
X509_Time X509_CRL::this_update() const
{
	return info.get1("X509.CRL.start");
}

/*
* Return the date when a new CRL will be issued
*/
X509_Time X509_CRL::next_update() const
{
	return info.get1("X509.CRL.end");
}

}
