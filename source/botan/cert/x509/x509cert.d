/*
* X.509 Certificates
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509cert;

public import botan.utils.datastor.datastor;
public import botan.pubkey.x509_key;
public import botan.cert.x509.x509_obj;
public import botan.asn1.x509_dn;
import botan.asn1.asn1_alt_name;
import botan.cert.x509.key_constraint;
import botan.cert.x509.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.internal.stl_util;
import botan.utils.parsing;
import botan.math.bigint.bigint;
import botan.libstate.lookup;
import botan.asn1.oid_lookup.oids;
import botan.codec.pem;
import botan.codec.hex;
import botan.utils.types;
import std.algorithm;
import iterator;
import std.array : Appender;

import botan.utils.hashmap;

alias X509_Certificate = FreeListRef!X509_Certificate_Impl;

/**
* This class represents X.509 Certificate
*/
final class X509_Certificate_Impl : X509_Object
{
public:
	/**
	* Get the public key associated with this certificate.
	* @return subject public key of this certificate
	*/
	Public_Key subject_public_key() const
	{
		return x509_key.load_key(
			asn1_obj.put_in_sequence(subject_public_key_bits()));
	}

	/**
	* Get the public key associated with this certificate.
	* @return subject public key of this certificate
	*/
	Vector!ubyte subject_public_key_bits() const
	{
		return hex_decode(m_subject.get1("X509.Certificate.public_key"));
	}

	/**
	* Get the issuer certificate DN.
	* @return issuer DN of this certificate
	*/
	X509_DN issuer_dn() const
	{
		return create_dn(m_issuer);
	}

	/**
	* Get the subject certificate DN.
	* @return subject DN of this certificate
	*/
	X509_DN subject_dn() const
	{
		return create_dn(m_subject);
	}

	/**
	* Get a value for a specific subject_info parameter name.
	* @param name the name of the paramter to look up. Possible names are
	* "X509.Certificate.version", "X509.Certificate.serial",
	* "X509.Certificate.start", "X509.Certificate.end",
	* "X509.Certificate.v2.key_id", "X509.Certificate.public_key",
	* "X509v3.BasicConstraints.path_constraint",
	* "X509v3.BasicConstraints.is_ca", "X509v3.ExtendedKeyUsage",
	* "X509v3.CertificatePolicies", "X509v3.SubjectKeyIdentifier" or
	* "X509.Certificate.serial".
	* @return value(s) of the specified parameter
	*/
	Vector!string
		subject_info(in string what) const
	{
		return m_subject.get(X509_DN.deref_info_field(what));
	}

	/**
	* Get a value for a specific subject_info parameter name.
	* @param name the name of the paramter to look up. Possible names are
	* "X509.Certificate.v2.key_id" or "X509v3.AuthorityKeyIdentifier".
	* @return value(s) of the specified parameter
	*/
	Vector!string issuer_info(in string what) const
	{
		return m_issuer.get(X509_DN.deref_info_field(what));
	}

	/**
	* Raw subject DN
	*/
	Vector!ubyte raw_issuer_dn() const
	{
		return m_issuer.get1_memvec("X509.Certificate.dn_bits");
	}


	/**
	* Raw issuer DN
	*/
	Vector!ubyte raw_subject_dn() const
	{
		return m_subject.get1_memvec("X509.Certificate.dn_bits");
	}

	/**
	* Get the notBefore of the certificate.
	* @return notBefore of the certificate
	*/
	string start_time() const
	{
		return m_subject.get1("X509.Certificate.start");
	}

	/**
	* Get the notAfter of the certificate.
	* @return notAfter of the certificate
	*/
	string end_time() const
	{
		return m_subject.get1("X509.Certificate.end");
	}

	/**
	* Get the X509 version of this certificate object.
	* @return X509 version
	*/
	uint x509_version() const
	{
		return (m_subject.get1_uint("X509.Certificate.version") + 1);
	}

	/**
	* Get the serial number of this certificate.
	* @return certificates serial number
	*/
	Vector!ubyte serial_number() const
	{
		return m_subject.get1_memvec("X509.Certificate.serial");
	}

	/**
	* Get the DER encoded AuthorityKeyIdentifier of this certificate.
	* @return DER encoded AuthorityKeyIdentifier
	*/
	Vector!ubyte authority_key_id() const
	{
		return m_issuer.get1_memvec("X509v3.AuthorityKeyIdentifier");
	}

	/**
	* Get the DER encoded SubjectKeyIdentifier of this certificate.
	* @return DER encoded SubjectKeyIdentifier
	*/
	Vector!ubyte subject_key_id() const
	{
		return m_subject.get1_memvec("X509v3.SubjectKeyIdentifier");
	}

	/**
	* Check whether this certificate is self signed.
	* @return true if this certificate is self signed
	*/
	bool is_self_signed() const { return m_self_signed; }

	/**
	* Check whether this certificate is a CA certificate.
	* @return true if this certificate is a CA certificate
	*/
	bool is_CA_cert() const
	{
		if (!m_subject.get1_uint("X509v3.BasicConstraints.is_ca"))
			return false;
		
		return allowed_usage(KEY_CERT_SIGN);
	}


	bool allowed_usage(Key_Constraints usage) const
	{
		if (constraints() == Key_Constraints.NO_CONSTRAINTS)
			return true;
		return (constraints() & usage);
	}

	/**
	* Returns true if and only if name (referring to an extended key
	* constraint, eg "PKIX.ServerAuth") is included in the extended
	* key extension.
	*/
	bool allowed_usage(in string usage) const
	{
		foreach (constraint; ex_constraints())
			if (constraint == usage)
				return true;
		
		return false;
	}

	/**
	* Get the path limit as defined in the BasicConstraints extension of
	* this certificate.
	* @return path limit
	*/
	uint path_limit() const
	{
		return m_subject.get1_uint("X509v3.BasicConstraints.path_constraint", 0);
	}

	/**
	* Get the key constraints as defined in the KeyUsage extension of this
	* certificate.
	* @return key constraints
	*/
	Key_Constraints constraints() const
	{
		return Key_Constraints(m_subject.get1_uint("X509v3.KeyUsage",
		                                         Key_Constraints.NO_CONSTRAINTS));
	}

	/**
	* Get the key constraints as defined in the ExtendedKeyUsage
	* extension of this
	* certificate.
	* @return key constraints
	*/
	Vector!string ex_constraints() const
	{
		return lookup_oids(m_subject.get("X509v3.ExtendedKeyUsage"));
	}

	/**
	* Get the policies as defined in the CertificatePolicies extension
	* of this certificate.
	* @return certificate policies
	*/
	Vector!string policies() const
	{
		return lookup_oids(m_subject.get("X509v3.CertificatePolicies"));
	}

	/**
	* Return the listed address of an OCSP responder, or empty if not set
	*/
	string ocsp_responder() const
	{
		return m_subject.get1("OCSP.responder", "");
	}

	/**
	* Return the CRL distribution point, or empty if not set
	*/
	string crl_distribution_point() const
	{
		return m_subject.get1("CRL.DistributionPoint", "");
	}

	/**
	* @return a string describing the certificate
	*/

	string toString() const
	{
		import std.array : Appender;
		__gshared immutable string[] dn_fields = [ "Name",
			"Email",
			"Organization",
			"Organizational Unit",
			"Locality",
			"State",
			"Country",
			"IP",
			"DNS",
			"URI",
			"PKIX.XMPPAddr" ];
		
		Appender!string output;
		
		foreach (const dn_field; dn_fields)
		{
			const Vector!string vals = subject_info(dn_field);
			
			if (vals.empty)
				continue;
			
			output ~= "Subject " ~ dn_field ~ ":";
			for (size_t j = 0; j != vals.length; ++j)
				output ~= " " ~ vals[j];
			output ~= "";
		}
		
		foreach (const dn_field; dn_fields)
		{
			const Vector!string vals = issuer_info(dn_field);
			
			if (vals.empty)
				continue;
			
			output ~= "Issuer " ~ dn_field ~ ":";
			for (size_t j = 0; j != vals.length; ++j)
				output ~= " " ~ vals[j];
			output ~= "";
		}
		
		output ~= "Version: " ~ x509_version();
		
		output ~= "Not valid before: " ~ start_time();
		output ~= "Not valid after: " ~ end_time();
		
		output ~= "Constraints:";
		Key_Constraints constraints = constraints();
		if (constraints == Key_Constraints.NO_CONSTRAINTS)
			output ~= " None";
		else
		{
			if (constraints & DIGITAL_SIGNATURE)
				output ~= "	Digital Signature";
			if (constraints & NON_REPUDIATION)
				output ~= "	Non-Repuidation";
			if (constraints & KEY_ENCIPHERMENT)
				output ~= "	Key Encipherment";
			if (constraints & DATA_ENCIPHERMENT)
				output ~= "	Data Encipherment";
			if (constraints & KEY_AGREEMENT)
				output ~= "	Key Agreement";
			if (constraints & KEY_CERT_SIGN)
				output ~= "	Cert Sign";
			if (constraints & CRL_SIGN)
				output ~= "	CRL Sign";
		}
		
		Vector!string policies = policies();
		if (!policies.empty)
		{
			output ~= "Policies: ";
			foreach (const policy; policies[])
				output ~= "	" ~ policy;
		}
		
		Vector!string ex_constraints = ex_constraints();
		if (!ex_constraints.empty)
		{
			output ~= "Extended Constraints:";
			foreach (const ex_constraint; ex_constraints[])
				output ~= "	" ~ ex_constraint;
		}
		
		if (ocsp_responder() != "")
			output ~= "OCSP responder " ~ ocsp_responder();
		if (crl_distribution_point() != "")
			output ~= "CRL " ~ crl_distribution_point();
		
		output ~= "Signature algorithm: " ~
			oids.lookup(signature_algorithm().oid);
		
		output ~= "Serial number: " ~ hex_encode(serial_number());
		
		if (authority_key_id().length)
			output ~= "Authority keyid: " ~ hex_encode(authority_key_id());
		
		if (subject_key_id().length)
			output ~= "Subject keyid: " ~ hex_encode(subject_key_id());
		
		Unique!X509_PublicKey pubkey = subject_public_key();
		output ~= "Public Key:" ~ x509_key.PEM_encode(*pubkey);
		
		return output.data;
	}


	/**
	* Return a fingerprint of the certificate
	*/
	string fingerprint(in string hash_name) const
	{
		Unique!HashFunction hash = get_hash(hash_name);
		hash.update(BER_encode());
		const auto hex_print = hex_encode(hash.flush());
		
		string formatted_print;
		
		for (size_t i = 0; i != hex_print.length; i += 2)
		{
			formatted_print.push_back(hex_print[i]);
			formatted_print.push_back(hex_print[i+1]);
			
			if (i != hex_print.length - 2)
				formatted_print.push_back(':');
		}
		
		return formatted_print;
	}

	/**
	* Check if a certain DNS name matches up with the information in
	* the cert
	*/
	bool matches_dns_name(in string name) const
	{
		if (name == "")
			return false;
		
		if (cert_subject_dns_match(name, subject_info("DNS")))
			return true;
		
		if (cert_subject_dns_match(name, subject_info("Name")))
			return true;
		
		return false;
	}

	/**
	* Check to certificates for equality.
	* @return true both certificates are (binary) equal
	*/
	bool opEquals(in X509_Certificate other) const
	{
		return (sig == other.sig &&
		        sig_algo == other.sig_algo &&
		        m_self_signed == other.m_self_signed &&
		        m_issuer == other.m_issuer &&
		        m_subject == other.m_subject);
	}

	/**
	* Impose an arbitrary (but consistent) ordering
	* @return true if this is less than other by some unspecified criteria
	*/
	bool opBinary(string op)(in X509_Certificate other) const
		if (op == "<")
	{
		/* If signature values are not equal, sort by lexicographic ordering of that */
		if (sig != other.sig)
		{
			if (sig < other.sig)
				return true;
			return false;
		}
		
		// Then compare the signed contents
		return tbs_bits < other.tbs_bits;
	}

	/**
	* Check two certificates for ineah jsais sadfadfasfaquality
	* @return true if the arguments represent different certificates,
	* false if they are binary identical
	*/
	bool opCmp(string op)(in X509_Certificate cert2)
		if (op == "!=")
	{
		return !(cert1 == cert2);
	}


	/**
	* Create a certificate from a data source providing the DER or
	* PEM encoded certificate.
	* @param source the data source
	*/
	this(DataSource input)
	{
		super(input, "CERTIFICATE/X509 CERTIFICATE");
		m_self_signed = false;
		do_decode();
	}

	/**
	* Create a certificate from a file containing the DER or PEM
	* encoded certificate.
	* @param filename the name of the certificate file
	*/
	this(in string filename)
	{
		super(filename, "CERTIFICATE/X509 CERTIFICATE");
		m_self_signed = false;
		do_decode();
	}

	this(in Vector!ubyte input)
	{
		super(input, "CERTIFICATE/X509 CERTIFICATE");
		m_self_signed = false;
		do_decode();
	}

private:
	/*
	* Decode the TBSCertificate data
	*/
	void force_decode()
	{
		size_t _version;
		BigInt serial_bn;
		Algorithm_Identifier sig_algo_inner;
		X509_DN dn_issuer, dn_subject;
		X509_Time start, end;
		
		BER_Decoder tbs_cert(tbs_bits);
		
		tbs_cert.decode_optional(_version, ASN1_Tag(0),
		                         ASN1_Tag(CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC))
			.decode(serial_bn)
				.decode(sig_algo_inner)
				.decode(dn_issuer)
				.start_cons(ASN1_Tag.SEQUENCE)
				.decode(start)
				.decode(end)
				.verify_end()
				.end_cons()
				.decode(dn_subject);
		
		if (_version > 2)
			throw new Decoding_Error("Unknown X.509 cert version " ~ std.conv.to!string(_version));
		if (sig_algo != sig_algo_inner)
			throw new Decoding_Error("Algorithm identifier mismatch");
		
		m_self_signed = (dn_subject == dn_issuer);
		
		m_subject.add(dn_subject.contents());
		m_issuer.add(dn_issuer.contents());
		
		m_subject.add("X509.Certificate.dn_bits", asn1_obj.put_in_sequence(dn_subject.get_bits()));
		m_issuer.add("X509.Certificate.dn_bits", asn1_obj.put_in_sequence(dn_issuer.get_bits()));
		
		BER_Object public_key = tbs_cert.get_next_object();
		if (public_key.type_tag != ASN1_Tag.SEQUENCE || public_key.class_tag != ASN1_Tag.CONSTRUCTED)
			throw new BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
			                      public_key.type_tag, public_key.class_tag);
		
		Vector!ubyte v2_issuer_key_id, v2_subject_key_id;
		
		tbs_cert.decode_optional_string(v2_issuer_key_id, ASN1_Tag.BIT_STRING, 1);
		tbs_cert.decode_optional_string(v2_subject_key_id, ASN1_Tag.BIT_STRING, 2);
		
		BER_Object v3_exts_data = tbs_cert.get_next_object();
		if (v3_exts_data.type_tag == 3 &&
		    v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC))
		{
			Extensions extensions;
			
			BER_Decoder(v3_exts_data.value).decode(extensions).verify_end();
			
			extensions.contents_to(m_subject, m_issuer);
		}
		else if (v3_exts_data.type_tag != ASN1_Tag.NO_OBJECT)
			throw new BER_Bad_Tag("Unknown tag in X.509 cert",
			                      v3_exts_data.type_tag, v3_exts_data.class_tag);
		
		if (tbs_cert.more_items())
			throw new Decoding_Error("TBSCertificate has more items that expected");
		
		m_subject.add("X509.Certificate.version", _version);
		m_subject.add("X509.Certificate.serial", BigInt.encode(serial_bn));
		m_subject.add("X509.Certificate.start", start.readable_string());
		m_subject.add("X509.Certificate.end", end.readable_string());
		
		m_issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
		m_subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);
		
		m_subject.add("X509.Certificate.public_key",
		            hex_encode(public_key.value));
		
		if (m_self_signed && _version == 0)
		{
			m_subject.add("X509v3.BasicConstraints.is_ca", 1);
			m_subject.add("X509v3.BasicConstraints.path_constraint", x509_ext.NO_CERT_PATH_LIMIT);
		}
		
		if (is_CA_cert() &&
		    !m_subject.has_value("X509v3.BasicConstraints.path_constraint"))
		{
			const size_t limit = (x509_version() < 3) ?
				x509_ext.NO_CERT_PATH_LIMIT : 0;
			
			m_subject.add("X509v3.BasicConstraints.path_constraint", limit);
		}
	}


	this() {}

	Data_Store m_subject, m_issuer;
	bool m_self_signed;
}


/*
* Data Store Extraction Operations
*/
/*
* Create and populate a X509_DN
*/
X509_DN create_dn(in Data_Store info)
{
	auto names = info.search_for((in string key, in string)
	{
		return (key.canFind("X520."));
	});
	
	X509_DN dn;
	
	for (auto i = names.ptr; i != names.end(); ++i)
		dn.add_attribute(i.first, i.second);
	
	return dn;
}


/*
* Create and populate an Alternative_Name
*/
Alternative_Name create_alt_name(in Data_Store info)
{
	auto names = info.search_for((in string key, in string)
									{
										return (key == "RFC822" ||
										        key == "DNS" ||
										        key == "URI" ||
										        key == "IP");
									});
	
	Alternative_Name alt_name;
	
	for (auto i = names.ptr; i != names.end(); ++i)
		alt_name.add_attribute(i.first, i.second);
	
	return alt_name;
}



/*
* Lookup each OID in the vector
*/
Vector!string lookup_oids(in Vector!string input)
{
	Vector!string output;
	
	for (auto i = input.ptr; i != input.end(); ++i)
		output.push_back(oids.lookup(OID(*i)));
	return output;
}


bool cert_subject_dns_match(in string name,
                            const Vector!string cert_names)
{
	foreach (const cn; cert_names)
	{
		if (cn == name)
			return true;
		
		/*
		* Possible wildcard match. We only support the most basic form of
		* cert wildcarding ala RFC 2595
		*/
		if (cn.length > 2 && cn[0] == '*' && cn[1] == '.' && name.length > cn.length)
		{
			const string base = cn[1 .. $];
			size_t start = name.length - base.length;
			if (name[start .. start + base.length] == base)
				return true;
		}
	}
	
	return false;
}