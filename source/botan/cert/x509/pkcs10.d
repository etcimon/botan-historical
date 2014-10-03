/*
* PKCS #10
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pkcs10;
import botan.x509_ext;
import botan.x509cert;
import botan.der_enc;
import botan.ber_dec;
import botan.parsing;
import botan.asn1.oid_lookup.oids;
import botan.pem;
/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(DataSource& input) :
	X509_Object(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
{
	do_decode();
}

/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(in string input) :
	X509_Object(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
{
	do_decode();
}

/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(in Vector!byte input) :
	X509_Object(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
{
	do_decode();
}

/*
* Deocde the CertificateRequestInfo
*/
void PKCS10_Request::force_decode()
{
	BER_Decoder cert_req_info(tbs_bits);

	size_t _version;
	cert_req_info.decode(_version);
	if (_version != 0)
		throw new Decoding_Error("Unknown version code in PKCS #10 request: " +
									std::to_string(_version));

	X509_DN dn_subject;
	cert_req_info.decode(dn_subject);

	info.add(dn_subject.contents());

	BER_Object public_key = cert_req_info.get_next_object();
	if (public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
		throw new BER_Bad_Tag("PKCS10_Request: Unexpected tag for public key",
								public_key.type_tag, public_key.class_tag);

	info.add("X509.Certificate.public_key",
				PEM_Code::encode(
					ASN1::put_in_sequence(unlock(public_key.value)),
					"PUBLIC KEY"
					)
		);

	BER_Object attr_bits = cert_req_info.get_next_object();

	if (attr_bits.type_tag == 0 &&
		attr_bits.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
	{
		BER_Decoder attributes(attr_bits.value);
		while(attributes.more_items())
		{
			Attribute attr;
			attributes.decode(attr);
			handle_attribute(attr);
		}
		attributes.verify_end();
	}
	else if (attr_bits.type_tag != NO_OBJECT)
		throw new BER_Bad_Tag("PKCS10_Request: Unexpected tag for attributes",
								attr_bits.type_tag, attr_bits.class_tag);

	cert_req_info.verify_end();

	if (!this.check_signature(subject_public_key()))
		throw new Decoding_Error("PKCS #10 request: Bad signature detected");
}

/*
* Handle attributes in a PKCS #10 request
*/
void PKCS10_Request::handle_attribute(in Attribute attr)
{
	BER_Decoder value(attr.parameters);

	if (attr.oid == oids.lookup("PKCS9.EmailAddress"))
	{
		ASN1_String email;
		value.decode(email);
		info.add("RFC822", email.value());
	}
	else if (attr.oid == oids.lookup("PKCS9.ChallengePassword"))
	{
		ASN1_String challenge_password;
		value.decode(challenge_password);
		info.add("PKCS9.ChallengePassword", challenge_password.value());
	}
	else if (attr.oid == oids.lookup("PKCS9.ExtensionRequest"))
	{
		Extensions extensions;
		value.decode(extensions).verify_end();

		Data_Store issuer_info;
		extensions.contents_to(info, issuer_info);
	}
}

/*
* Return the challenge password (if any)
*/
string PKCS10_Request::challenge_password() const
{
	return info.get1("PKCS9.ChallengePassword");
}

/*
* Return the name of the requestor
*/
X509_DN PKCS10_Request::subject_dn() const
{
	return create_dn(info);
}

/*
* Return the public key of the requestor
*/
Vector!byte PKCS10_Request::raw_public_key() const
{
	DataSource_Memory source(info.get1("X509.Certificate.public_key"));
	return unlock(PEM_Code::decode_check_label(source, "PUBLIC KEY"));
}

/*
* Return the public key of the requestor
*/
Public_Key* PKCS10_Request::subject_public_key() const
{
	DataSource_Memory source(info.get1("X509.Certificate.public_key"));
	return X509::load_key(source);
}

/*
* Return the alternative names of the requestor
*/
AlternativeName PKCS10_Request::subject_alt_name() const
{
	return create_alt_name(info);
}

/*
* Return the key constraints (if any)
*/
Key_Constraints PKCS10_Request::constraints() const
{
	return Key_Constraints(info.get1_uint("X509v3.KeyUsage", NO_CONSTRAINTS));
}

/*
* Return the extendend key constraints (if any)
*/
Vector!( OID ) PKCS10_Request::ex_constraints() const
{
	Vector!string oids = info.get("X509v3.ExtendedKeyUsage");

	Vector!( OID ) result;
	for (size_t i = 0; i != oids.size(); ++i)
		result.push_back(OID(oids[i]));
	return result;
}

/*
* Return is a CA certificate is requested
*/
bool PKCS10_Request::is_CA() const
{
	return (info.get1_uint("X509v3.BasicConstraints.is_ca") > 0);
}

/*
* Return the desired path limit (if any)
*/
uint PKCS10_Request::path_limit() const
{
	return info.get1_uint("X509v3.BasicConstraints.path_constraint", 0);
}

}
