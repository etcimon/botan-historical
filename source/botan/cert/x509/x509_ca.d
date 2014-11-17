/*
* X.509 Certificate Authority
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_ca;

import botan.asn1.asn1_time;
import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.cert.x509.x509_ext;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.cert.x509.pkcs10;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.libstate.lookup;
import botan.asn1.oid_lookup.oids;
import botan.cert.x509.key_constraint;
import botan.rng.rng;
import std.datetime;
import std.algorithm;

/**
* This class represents X.509 Certificate Authorities (CAs).
*/
struct X509_CA
{
public:

	/**
	* Sign a PKCS#10 Request.
	* @param req the request to sign
	* @param rng the rng to use
	* @param not_before the starting time for the certificate
	* @param not_after the expiration time for the certificate
	* @return resulting certificate
	*/
	X509_Certificate sign_request(in PKCS10_Request req,
	                              RandomNumberGenerator rng,
	                              in X509_Time not_before,
	                              in X509_Time not_after)
	{
		Key_Constraints constraints;
		if (req.is_CA())
			constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
		else
		{
			Unique!Public_Key key = req.subject_public_key();
			constraints = find_constraints(*key, req.constraints());
		}

		Extensions extensions;
		
		extensions.add(new x509_ext.Basic_Constraints(req.is_CA(), req.path_limit()), true);
		
		extensions.add(new x509_ext.Key_Usage(constraints), true);
		
		extensions.add(new x509_ext.Authority_Key_ID(m_cert.subject_key_id()));
		extensions.add(new x509_ext.Subject_Key_ID(req.raw_public_key()));
		
		extensions.add(new x509_ext.Subject_Alternative_Name(req.subject_alt_name()));
		
		extensions.add(new x509_ext.Extended_Key_Usage(req.ex_constraints()));
		
		return make_cert(m_signer, rng, m_ca_sig_algo,
		                 req.raw_public_key(),
		                 not_before, not_after,
		                 m_cert.subject_dn(), req.subject_dn(),
		                 extensions);
	}

	/**
	* Get the certificate of this CA.
	* @return CA certificate
	*/
	X509_Certificate ca_certificate() const
	{
		return m_cert;
	}

	/**
	* Create a new and empty CRL for this CA.
	* @param rng the random number generator to use
	* @param next_update the time to set in next update in seconds
	* as the offset from the current time
	* @return new CRL
	*/
	X509_CRL new_crl(RandomNumberGenerator rng, Duration next_update = 0.seconds) const
	{
		Vector!CRL_Entry empty;
		return make_crl(empty, 1, next_update, rng);
	}

	/**
	* Create a new CRL by with additional entries.
	* @param last_crl the last CRL of this CA to add the new entries to
	* @param new_entries contains the new CRL entries to be added to the CRL
	* @param rng the random number generator to use
	* @param next_update the time to set in next update in seconds
	* as the offset from the current time
	*/
	X509_CRL update_crl(in X509_CRL crl,
	                    in Vector!CRL_Entry new_revoked,
	                    RandomNumberGenerator rng,
	                    Duration next_update = 0.seconds) const
	{

		Vector!CRL_Entry revoked = crl.get_revoked();
		new_revoked = revoked.dup;
		
		return make_crl(revoked, crl.crl_number() + 1, next_update, rng);
	}


	/**
	* Interface for creating new certificates
	* @param signer a signing object
	* @param rng a random number generator
	* @param sig_algo the signature algorithm identifier
	* @param pub_key the serialized public key
	* @param not_before the start time of the certificate
	* @param not_after the end time of the certificate
	* @param issuer_dn the DN of the issuer
	* @param subject_dn the DN of the subject
	* @param extensions an optional list of certificate extensions
	* @returns newly minted certificate
	*/
	static X509_Certificate make_cert(ref PK_Signer signer,
			                          RandomNumberGenerator rng,
			                          in Algorithm_Identifier sig_algo,
			                          in Vector!ubyte pub_key,
			                          in X509_Time not_before,
			                          in X509_Time not_after,
			                          in X509_DN issuer_dn,
			                          in X509_DN subject_dn,
			                          in Extensions extensions)
	{
		__gshared immutable size_t X509_CERT_VERSION = 3;
		__gshared immutable size_t SERIAL_BITS = 128;
		
		BigInt serial_no = BigInt(rng, SERIAL_BITS);
		
		const Vector!ubyte cert = X509_Object.make_signed(
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

	/**
	* Create a new CA object. Load the certificate and private key
	* @param ca_certificate the certificate of the CA
	* @param key the private key of the CA
	* @param hash_fn name of a hash function to use for signing
	*/
	this(in X509_Certificate c,
	     in Private_Key key,
	     in string hash_fn)
	{
		m_cert = c;
		if (!m_cert.is_CA_cert())
			throw new Invalid_Argument("X509_CA: This certificate is not for a CA");
		
		m_signer = choose_sig_format(key, hash_fn, m_ca_sig_algo);
	}

	/*
	* X509_CA Destructor
	*/
	~this()
	{
	}
private:
	/*
	* Create a CRL
	*/
	X509_CRL make_crl(in Vector!CRL_Entry revoked,
	                  uint crl_number, Duration next_update,
	                  RandomNumberGenerator rng) const
	{
		__gshared immutable size_t X509_CRL_VERSION = 2;
		
		if (next_update == 0.seconds)
			next_update = 7.days;
		
		// Totally stupid: ties encoding logic to the return of std::time!!
		auto current_time = Clock.currTime();
		auto expire_time = current_time + next_update;
		
		Extensions extensions;
		extensions.add(new x509_ext.Authority_Key_ID(m_cert.subject_key_id()));
		extensions.add(new x509_ext.CRL_Number(crl_number));
		
		const Vector!ubyte crl = x509_obj.make_signed(
			m_signer, rng, m_ca_sig_algo,
			DER_Encoder().start_cons(ASN1_Tag.SEQUENCE)
			.encode(X509_CRL_VERSION-1)
			.encode(m_ca_sig_algo)
			.encode(m_cert.issuer_dn())
			.encode(X509_Time(current_time))
			.encode(X509_Time(expire_time))
			.encode_if (revoked.length > 0,
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


	Algorithm_Identifier m_ca_sig_algo;
	X509_Certificate m_cert;
	PK_Signer m_signer;
}

/**
* Choose the default signature format for a certain public key signature
* scheme.
* @param key will be the key to choose a padding scheme for
* @param hash_fn is the desired hash function
* @param alg_id will be set to the chosen scheme
* @return A PK_Signer object for generating signatures
*/
/*
* Choose a signing format for the key
*/
PK_Signer choose_sig_format(in Private_Key key,
                            in string hash_fn,
                            Algorithm_Identifier sig_algo)
{
	import std.array : Appender;
	Appender!string padding;
	
	const string algo_name = key.algo_name;
	
	const HashFunction proto_hash = retrieve_hash(hash_fn);
	if (!proto_hash)
		throw new Algorithm_Not_Found(hash_fn);
	
	if (key.max_input_bits() < proto_hash.output_length*8)
		throw new Invalid_Argument("Key is too small for chosen hash function");
	
	if (algo_name == "RSA")
		padding ~= "EMSA3";
	else if (algo_name == "DSA")
		padding ~= "EMSA1";
	else if (algo_name == "ECDSA")
		padding ~= "EMSA1_BSI";
	else
		throw new Invalid_Argument("Unknown X.509 signing key type: " ~ algo_name);
	
	Signature_Format format = (key.message_parts() > 1) ? DER_SEQUENCE : IEEE_1363;

	padding ~= padding.data ~ '(' ~ proto_hash.name ~ ')';
	
	sig_algo.oid = oids.lookup(algo_name ~ "/" ~ padding.data);
	sig_algo.parameters = key.algorithm_identifier().parameters;
	
	return PK_Signer(key, padding.data, format);
}