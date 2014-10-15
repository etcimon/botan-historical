/*
* X.509 Self-Signed Certificate
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509self;

import botan.cert.x509.x509cert;
import botan.pkcs8;
import botan.cert.x509.pkcs10;
import botan.asn1.asn1_time;
import botan.asn1.oid_lookup.oids;
import botan.parsing;
import std.datetime;
import botan.cert.x509.x509_ext;
import botan.cert.x509.x509_ca;
import botan.asn1.der_enc;
import botan.asn1.oid_lookup.oids;
import botan.filters.pipe;
/**
* Options for X.509 certificates.
*/
class X509_Cert_Options
{
public:
	/**
	* the subject common name
	*/
	string common_name;

	/**
	* the subject counry
	*/
	string country;

	/**
	* the subject organization
	*/
	string organization;

	/**
	* the subject organizational unit
	*/
	string org_unit;

	/**
	* the subject locality
	*/
	string locality;

	/**
	* the subject state
	*/
	string state;

	/**
	* the subject serial number
	*/
	string serial_number;

	/**
	* the subject email adress
	*/
	string email;

	/**
	* the subject URI
	*/
	string uri;

	/**
	* the subject IPv4 address
	*/
	string ip;

	/**
	* the subject DNS
	*/
	string dns;

	/**
	* the subject XMPP
	*/
	string xmpp;

	/**
	* the subject challenge password
	*/
	string challenge;

	/**
	* the subject notBefore
	*/
	X509_Time start;
	/**
	* the subject notAfter
	*/
	X509_Time end;

	/**
	* Indicates whether the certificate request
	*/
	bool is_CA;

	/**
	* Indicates the BasicConstraints path limit
	*/
	size_t path_limit;

	/**
	* The key constraints for the subject public key
	*/
	Key_Constraints constraints;

	/**
	* The key extended constraints for the subject public key
	*/
	Vector!( OID ) ex_constraints;

	/**
	* Check the options set in this object for validity.
	*/
	void sanity_check() const
	{
		if (common_name == "" || country == "")
			throw new Encoding_Error("X.509 certificate: name and country MUST be set");
		if (country.size() != 2)
			throw new Encoding_Error("Invalid ISO country code: " ~ country);
		if (start >= end)
			throw new Encoding_Error("X509_Cert_Options: invalid time constraints");
	}
	


	/**
	* Mark the certificate as a CA certificate and set the path limit.
	* @param limit the path limit to be set in the BasicConstraints extension.
	*/
	void CA_key(size_t limit = 1)
	{
		is_CA = true;
		path_limit = limit;
	}


	/**
	* Set when the certificate should become valid
	* @param time the notBefore value of the certificate
	*/
	void not_before(in string time_string)
	{
		start = X509_Time(time_string);
	}

	/**
	* Set the notAfter of the certificate.
	* @param time the notAfter value of the certificate
	*/
	void not_after(in string time_string)
	{
		end = X509_Time(time_string);
	}

	/**
	* Add the key constraints of the KeyUsage extension.
	* @param constr the constraints to set
	*/
	void add_constraints(Key_Constraints usage)
	{
		constraints = usage;
	}

	/**
	* Add constraints to the ExtendedKeyUsage extension.
	* @param oid the oid to add
	*/
	void add_ex_constraint(in OID oid)
	{
		ex_constraints.push_back(oid);
	}

	/**
	* Add constraints to the ExtendedKeyUsage extension.
	* @param name the name to look up the oid to add
	*/
	void add_ex_constraint(in string oid_str)
	{
		ex_constraints.push_back(oids.lookup(oid_str));
	}

	/**
	* Construct a new options object
	* @param opts define the common name of this object. An example for this
	* parameter would be "common_name/country/organization/organizational_unit".
	* @param expire_time the expiration time (default 1 year)
	*/
	this(in string initial_opts = "",
	                  Duration expiration_time = 365.days)
	{
		is_CA = false;
		path_limit = 0;
		constraints = Key_Constraints.NO_CONSTRAINTS;
		
		auto now = Clock.currTime();
		
		start = X509_Time(now);
		end = X509_Time(now + expiration_time);
		
		if (initial_opts == "")
			return;
		
		Vector!string parsed = std.algorithm.splitter(initial_opts, '/');
		
		if (parsed.size() > 4)
			throw new Invalid_Argument("X.509 cert options: Too many names: "
			                           + initial_opts);
		
		if (parsed.size() >= 1) common_name  = parsed[0];
		if (parsed.size() >= 2) country		= parsed[1];
		if (parsed.size() >= 3) organization = parsed[2];
		if (parsed.size() == 4) org_unit	  = parsed[3];
	}
};

/**
* Create a self-signed X.509 certificate.
* @param opts the options defining the certificate to create
* @param key the private key used for signing, i.e. the key
* associated with this self-signed certificate
* @param hash_fn the hash function to use
* @param rng the rng to use
* @return newly created self-signed certificate
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
	
	Vector!ubyte pub_key = x509_key.BER_encode(key);
	Unique!PK_Signer signer = choose_sig_format(key, hash_fn, sig_algo);
	load_info(opts, subject_dn, subject_alt);
	
	Key_Constraints constraints;
	if (opts.is_CA)
		constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
	else
		constraints = find_constraints(key, opts.constraints);
	
	Extensions extensions;
	
	extensions.add(
		new x509_ext.Basic_Constraints(opts.is_CA, opts.path_limit),
		true);
	
	extensions.add(new x509_ext.Key_Usage(constraints), true);
	
	extensions.add(new x509_ext.Subject_Key_ID(pub_key));
	
	extensions.add(
		new x509_ext.Subject_Alternative_Name(subject_alt));
	
	extensions.add(
		new x509_ext.Extended_Key_Usage(opts.ex_constraints));
	
	return X509_CA.make_cert(signer.get(), rng, sig_algo, pub_key,
	                          opts.start, opts.end,
	                          subject_dn, subject_dn,
	                          extensions);
}

/**
* Create a PKCS#10 certificate request.
* @param opts the options defining the request to create
* @param key the key used to sign this request
* @param rng the rng to use
* @param hash_fn the hash function to use
* @return newly created PKCS#10 request
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
	
	Vector!ubyte pub_key = x509_key.BER_encode(key);
	Unique!PK_Signer signer = choose_sig_format(key, hash_fn, sig_algo);
	load_info(opts, subject_dn, subject_alt);
	
	const size_t PKCS10_VERSION = 0;
	
	Extensions extensions;
	
	extensions.add(
		new x509_ext.Basic_Constraints(opts.is_CA, opts.path_limit));
	extensions.add(
		new x509_ext.Key_Usage(
		opts.is_CA ? Key_Constraints(KEY_CERT_SIGN | CRL_SIGN) :
		find_constraints(key, opts.constraints)
		)
		);
	extensions.add(
		new x509_ext.Extended_Key_Usage(opts.ex_constraints));
	extensions.add(
		new x509_ext.Subject_Alternative_Name(subject_alt));
	
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
		X509_Object.make_signed(signer.get(), rng, sig_algo,
		                         tbs_req.get_contents());
	
	return PKCS10_Request(req);
}

/*
* Load information from the X509_Cert_Options
*/
private void load_info(in X509_Cert_Options opts, ref X509_DN subject_dn,
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