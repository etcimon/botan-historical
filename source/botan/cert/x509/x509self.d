/*
* PKCS #10/Self Signed Cert Creation
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509self;
import botan.x509_ext;
import botan.x509_ca;
import botan.asn1.der_enc;
import botan.asn1.oid_lookup.oids;
import botan.pipe;
namespace {

/*
* Load information from the X509_Cert_Options
*/
void load_info(in X509_Cert_Options opts, ref X509_DN subject_dn,
					ref AlternativeName subject_alt)
{
	subject_dn.add_attribute("X520.CommonName", opts.common_name);
	subject_dn.add_attribute("X520.Country", opts.country);
	subject_dn.add_attribute("X520.State", opts.state);
	subject_dn.add_attribute("X520.Locality", opts.locality);
	subject_dn.add_attribute("X520.Organization", opts.organization);
	subject_dn.add_attribute("X520.OrganizationalUnit", opts.org_unit);
	subject_dn.add_attribute("X520.SerialNumber", opts.serial_number);
	subject_alt = AlternativeName(opts.email, opts.uri, opts.dns, opts.ip);
	subject_alt.add_othername(oids.lookup("PKIX.XMPPAddr"),
		                          opts.xmpp, ASN1_Tag.UTF8_STRING);
}

}

namespace X509 {

/*
* Create a new self-signed X.509 certificate
*/
X509_Certificate create_self_signed_cert(in X509_Cert_Options opts,
													  in Private_Key key,
													  in string hash_fn,
													  RandomNumberGenerator rng)
{
	AlgorithmIdentifier sig_algo;
	X509_DN subject_dn;
	AlternativeName subject_alt;

	opts.sanity_check();

	Vector!ubyte pub_key = X509::BER_encode(key);
	Unique!PK_Signer signer(choose_sig_format(key, hash_fn, sig_algo));
	load_info(opts, subject_dn, subject_alt);

	Key_Constraints constraints;
	if (opts.is_CA)
		constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
	else
		constraints = find_constraints(key, opts.constraints);

	Extensions extensions;

	extensions.add(
		new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit),
		true);

	extensions.add(new Cert_Extension::Key_Usage(constraints), true);

	extensions.add(new Cert_Extension::Subject_Key_ID(pub_key));

	extensions.add(
		new Cert_Extension::Subject_Alternative_Name(subject_alt));

	extensions.add(
		new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));

	return X509_CA::make_cert(signer.get(), rng, sig_algo, pub_key,
									  opts.start, opts.end,
									  subject_dn, subject_dn,
									  extensions);
}

/*
* Create a PKCS #10 certificate request
*/
PKCS10_Request create_cert_req(in X509_Cert_Options opts,
										 in Private_Key key,
										 in string hash_fn,
										 RandomNumberGenerator rng)
{
	AlgorithmIdentifier sig_algo;
	X509_DN subject_dn;
	AlternativeName subject_alt;

	opts.sanity_check();

	Vector!ubyte pub_key = X509::BER_encode(key);
	Unique!PK_Signer signer(choose_sig_format(key, hash_fn, sig_algo));
	load_info(opts, subject_dn, subject_alt);

	const size_t PKCS10_VERSION = 0;

	Extensions extensions;

	extensions.add(
		new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));
	extensions.add(
		new Cert_Extension::Key_Usage(
			opts.is_CA ? Key_Constraints(KEY_CERT_SIGN | CRL_SIGN) :
							 find_constraints(key, opts.constraints)
			)
		);
	extensions.add(
		new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));
	extensions.add(
		new Cert_Extension::Subject_Alternative_Name(subject_alt));

	DER_Encoder tbs_req;

	tbs_req.start_cons(ASN1_Tag.SEQUENCE)
		.encode(PKCS10_VERSION)
		.encode(subject_dn)
		.raw_bytes(pub_key)
		.start_explicit(0);

	if (opts.challenge != "")
	{
		ASN1_String challenge(opts.challenge, ASN1_Tag.DIRECTORY_STRING);

		tbs_req.encode(
			Attribute("PKCS9.ChallengePassword",
						 DER_Encoder().encode(challenge).get_contents_unlocked()
				)
			);
	}

	tbs_req.encode(
		Attribute("PKCS9.ExtensionRequest",
					 DER_Encoder()
						 .start_cons(ASN1_Tag.SEQUENCE)
							 .encode(extensions)
						 .end_cons()
					.get_contents_unlocked()
			)
		)
		.end_explicit()
		.end_cons();

	const Vector!ubyte req =
		X509_Object::make_signed(signer.get(), rng, sig_algo,
										 tbs_req.get_contents());

	return PKCS10_Request(req);
}

}

}
