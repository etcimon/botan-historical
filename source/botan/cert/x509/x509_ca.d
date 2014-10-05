/*
* X.509 Certificate Authority
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509_ca;
import botan.pubkey;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.bigint;
import botan.parsing;
import botan.lookup;
import botan.asn1.oid_lookup.oids;
import botan.key_constraint;
import algorithm;
import typeinfo;
import iterator;
import set;
/*
* Load the certificate and private key
*/
X509_CA::X509_CA(in X509_Certificate c,
					  in Private_Key key,
					  in string hash_fn) : cert(c)
{
	if (!cert.is_CA_cert())
		throw new Invalid_Argument("X509_CA: This certificate is not for a CA");

	signer = choose_sig_format(key, hash_fn, ca_sig_algo);
}

/*
* X509_CA Destructor
*/
X509_CA::~this()
{
	delete signer;
}

/*
* Sign a PKCS #10 certificate request
*/
X509_Certificate X509_CA::sign_request(in PKCS10_Request req,
													RandomNumberGenerator rng,
													const X509_Time& not_before,
													const X509_Time& not_after)
{
	Key_Constraints constraints;
	if (req.is_CA())
		constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
	else
	{
		Unique!Public_Key key(req.subject_public_key());
		constraints = find_constraints(*key, req.constraints());
	}

	Extensions extensions;

	extensions.add(
		new Cert_Extension::Basic_Constraints(req.is_CA(), req.path_limit()),
		true);

	extensions.add(new Cert_Extension::Key_Usage(constraints), true);

	extensions.add(new Cert_Extension::Authority_Key_ID(cert.subject_key_id()));
	extensions.add(new Cert_Extension::Subject_Key_ID(req.raw_public_key()));

	extensions.add(
		new Cert_Extension::Subject_Alternative_Name(req.subject_alt_name()));

	extensions.add(
		new Cert_Extension::Extended_Key_Usage(req.ex_constraints()));

	return make_cert(signer, rng, ca_sig_algo,
						  req.raw_public_key(),
						  not_before, not_after,
						  cert.subject_dn(), req.subject_dn(),
						  extensions);
}

/*
* Create a new certificate
*/
X509_Certificate X509_CA::make_cert(PK_Signer* signer,
												RandomNumberGenerator rng,
												const AlgorithmIdentifier& sig_algo,
												in Vector!ubyte pub_key,
												const X509_Time& not_before,
												const X509_Time& not_after,
												const X509_DN& issuer_dn,
												const X509_DN& subject_dn,
												const Extensions& extensions)
{
	const size_t X509_CERT_VERSION = 3;
	const size_t SERIAL_BITS = 128;

	BigInt serial_no(rng, SERIAL_BITS);

	const Vector!ubyte cert = X509_Object::make_signed(
		signer, rng, sig_algo,
		DER_Encoder().start_cons(ASN1_Tag.SEQUENCE)
			.start_explicit(0)
				.encode(X509_CERT_VERSION-1)
			.end_explicit()

			.encode(serial_no)

			.encode(sig_algo)
			.encode(issuer_dn)

			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(not_before)
				.encode(not_after)
			.end_cons()

			.encode(subject_dn)
			.raw_bytes(pub_key)

			.start_explicit(3)
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(extensions)
				 .end_cons()
			.end_explicit()
		.end_cons()
		.get_contents());

	return X509_Certificate(cert);
}

/*
* Create a new, empty CRL
*/
X509_CRL X509_CA::new_crl(RandomNumberGenerator rng,
								  uint next_update) const
{
	Vector!( CRL_Entry ) empty;
	return make_crl(empty, 1, next_update, rng);
}

/*
* Update a CRL with new entries
*/
X509_CRL X509_CA::update_crl(in X509_CRL crl,
									  const Vector!( CRL_Entry )& new_revoked,
									  RandomNumberGenerator rng,
									  uint next_update) const
{
	Vector!( CRL_Entry ) revoked = crl.get_revoked();

	std::copy(new_revoked.begin(), new_revoked.end(),
				 std::back_inserter(revoked));

	return make_crl(revoked, crl.crl_number() + 1, next_update, rng);
}

/*
* Create a CRL
*/
X509_CRL X509_CA::make_crl(in Vector!( CRL_Entry ) revoked,
									uint crl_number, uint next_update,
									RandomNumberGenerator rng) const
{
	const size_t X509_CRL_VERSION = 2;

	if (next_update == 0)
		next_update = timespec_to_uint("7d");

	// Totally stupid: ties encoding logic to the return of std::time!!
	auto current_time = std::chrono::system_clock::now();
	auto expire_time = current_time + std::chrono::seconds(next_update);

	Extensions extensions;
	extensions.add(
		new Cert_Extension::Authority_Key_ID(cert.subject_key_id()));
	extensions.add(new Cert_Extension::CRL_Number(crl_number));

	const Vector!ubyte crl = X509_Object::make_signed(
		signer, rng, ca_sig_algo,
		DER_Encoder().start_cons(ASN1_Tag.SEQUENCE)
			.encode(X509_CRL_VERSION-1)
			.encode(ca_sig_algo)
			.encode(cert.issuer_dn())
			.encode(X509_Time(current_time))
			.encode(X509_Time(expire_time))
			.encode_if (revoked.size() > 0,
				  DER_Encoder()
					  .start_cons(ASN1_Tag.SEQUENCE)
						  .encode_list(revoked)
					  .end_cons()
				)
			.start_explicit(0)
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(extensions)
				.end_cons()
			.end_explicit()
		.end_cons()
		.get_contents());

	return X509_CRL(crl);
}

/*
* Return the CA's certificate
*/
X509_Certificate X509_CA::ca_certificate() const
{
	return cert;
}

/*
* Choose a signing format for the key
*/
PK_Signer* choose_sig_format(in Private_Key key,
									  in string hash_fn,
									  AlgorithmIdentifier& sig_algo)
{
	string padding;

	const string algo_name = key.algo_name();

	const HashFunction proto_hash = retrieve_hash(hash_fn);
	if (!proto_hash)
		throw new Algorithm_Not_Found(hash_fn);

	if (key.max_input_bits() < proto_hash.output_length()*8)
		throw new Invalid_Argument("Key is too small for chosen hash function");

	if (algo_name == "RSA")
		padding = "EMSA3";
	else if (algo_name == "DSA")
		padding = "EMSA1";
	else if (algo_name == "ECDSA")
		padding = "EMSA1_BSI";
	else
		throw new Invalid_Argument("Unknown X.509 signing key type: " ~ algo_name);

	Signature_Format format =
		(key.message_parts() > 1) ? DER_SEQUENCE : IEEE_1363;

	padding = padding + '(' + proto_hash.name() + ')';

	sig_algo.oid = oids.lookup(algo_name ~ "/" ~ padding);
	sig_algo.parameters = key.algorithm_identifier().parameters;

	return new PK_Signer(key, padding, format);
}

}
