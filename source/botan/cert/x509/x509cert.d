/*
* X.509 Certificates
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509cert;
import botan.x509_ext;
import botan.der_enc;
import botan.ber_dec;
import botan.internal.stl_util;
import botan.parsing;
import botan.bigint;
import botan.lookup;
import botan.oids;
import botan.pem;
import botan.hex;
import algorithm;
import iterator;
import sstream;
namespace {

/*
* Lookup each OID in the vector
*/
Vector!( string ) lookup_oids(in Vector!( string ) input)
{
	Vector!( string ) output;

	for (auto i = input.begin(); i != input.end(); ++i)
		output.push_back(OIDS::lookup(OID(*i)));
	return output;
}

}

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(DataSource& input) :
	X509_Object(input, "CERTIFICATE/X509 CERTIFICATE")
{
	self_signed = false;
	do_decode();
}

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(in string input) :
	X509_Object(input, "CERTIFICATE/X509 CERTIFICATE")
{
	self_signed = false;
	do_decode();
}

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(in Vector!byte input) :
	X509_Object(input, "CERTIFICATE/X509 CERTIFICATE")
{
	self_signed = false;
	do_decode();
}

/*
* Decode the TBSCertificate data
*/
void X509_Certificate::force_decode()
{
	size_t _version;
	BigInt serial_bn;
	AlgorithmIdentifier sig_algo_inner;
	X509_DN dn_issuer, dn_subject;
	X509_Time start, end;

	BER_Decoder tbs_cert(tbs_bits);

	tbs_cert.decode_optional(_version, ASN1_Tag(0),
									 ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
		.decode(serial_bn)
		.decode(sig_algo_inner)
		.decode(dn_issuer)
		.start_cons(SEQUENCE)
			.decode(start)
			.decode(end)
			.verify_end()
		.end_cons()
		.decode(dn_subject);

	if (_version > 2)
		throw new Decoding_Error("Unknown X.509 cert version " + std::to_string(_version));
	if (sig_algo != sig_algo_inner)
		throw new Decoding_Error("Algorithm identifier mismatch");

	self_signed = (dn_subject == dn_issuer);

	subject.add(dn_subject.contents());
	issuer.add(dn_issuer.contents());

	subject.add("X509.Certificate.dn_bits", ASN1::put_in_sequence(dn_subject.get_bits()));
	issuer.add("X509.Certificate.dn_bits", ASN1::put_in_sequence(dn_issuer.get_bits()));

	BER_Object public_key = tbs_cert.get_next_object();
	if (public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
		throw new BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
								public_key.type_tag, public_key.class_tag);

	Vector!( byte ) v2_issuer_key_id, v2_subject_key_id;

	tbs_cert.decode_optional_string(v2_issuer_key_id, BIT_STRING, 1);
	tbs_cert.decode_optional_string(v2_subject_key_id, BIT_STRING, 2);

	BER_Object v3_exts_data = tbs_cert.get_next_object();
	if (v3_exts_data.type_tag == 3 &&
		v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
	{
		Extensions extensions;

		BER_Decoder(v3_exts_data.value).decode(extensions).verify_end();

		extensions.contents_to(subject, issuer);
	}
	else if (v3_exts_data.type_tag != NO_OBJECT)
		throw new BER_Bad_Tag("Unknown tag in X.509 cert",
								v3_exts_data.type_tag, v3_exts_data.class_tag);

	if (tbs_cert.more_items())
		throw new Decoding_Error("TBSCertificate has more items that expected");

	subject.add("X509.Certificate.version", _version);
	subject.add("X509.Certificate.serial", BigInt::encode(serial_bn));
	subject.add("X509.Certificate.start", start.readable_string());
	subject.add("X509.Certificate.end", end.readable_string());

	issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
	subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);

	subject.add("X509.Certificate.public_key",
					hex_encode(public_key.value));

	if (self_signed && _version == 0)
	{
		subject.add("X509v3.BasicConstraints.is_ca", 1);
		subject.add("X509v3.BasicConstraints.path_constraint", Cert_Extension::NO_CERT_PATH_LIMIT);
	}

	if (is_CA_cert() &&
		!subject.has_value("X509v3.BasicConstraints.path_constraint"))
	{
		const size_t limit = (x509_version() < 3) ?
		  Cert_Extension::NO_CERT_PATH_LIMIT : 0;

		subject.add("X509v3.BasicConstraints.path_constraint", limit);
	}
}

/*
* Return the X.509 version in use
*/
uint X509_Certificate::x509_version() const
{
	return (subject.get1_uint("X509.Certificate.version") + 1);
}

/*
* Return the time this cert becomes valid
*/
string X509_Certificate::start_time() const
{
	return subject.get1("X509.Certificate.start");
}

/*
* Return the time this cert becomes invalid
*/
string X509_Certificate::end_time() const
{
	return subject.get1("X509.Certificate.end");
}

/*
* Return information about the subject
*/
Vector!( string )
X509_Certificate::subject_info(in string what) const
{
	return subject.get(X509_DN::deref_info_field(what));
}

/*
* Return information about the issuer
*/
Vector!( string )
X509_Certificate::issuer_info(in string what) const
{
	return issuer.get(X509_DN::deref_info_field(what));
}

/*
* Return the public key in this certificate
*/
Public_Key* X509_Certificate::subject_public_key() const
{
	return X509::load_key(
		ASN1::put_in_sequence(this->subject_public_key_bits()));
}

Vector!( byte ) X509_Certificate::subject_public_key_bits() const
{
	return hex_decode(subject.get1("X509.Certificate.public_key"));
}

/*
* Check if the certificate is for a CA
*/
bool X509_Certificate::is_CA_cert() const
{
	if (!subject.get1_uint("X509v3.BasicConstraints.is_ca"))
		return false;

	return allowed_usage(KEY_CERT_SIGN);
}

bool X509_Certificate::allowed_usage(Key_Constraints usage) const
{
	if (constraints() == NO_CONSTRAINTS)
		return true;
	return (constraints() & usage);
}

bool X509_Certificate::allowed_usage(in string usage) const
{
	foreach (constraint; ex_constraints())
		if (constraint == usage)
			return true;

	return false;
}

/*
* Return the path length constraint
*/
uint X509_Certificate::path_limit() const
{
	return subject.get1_uint("X509v3.BasicConstraints.path_constraint", 0);
}

/*
* Return the key usage constraints
*/
Key_Constraints X509_Certificate::constraints() const
{
	return Key_Constraints(subject.get1_uint("X509v3.KeyUsage",
															 NO_CONSTRAINTS));
}

/*
* Return the list of extended key usage OIDs
*/
Vector!( string ) X509_Certificate::ex_constraints() const
{
	return lookup_oids(subject.get("X509v3.ExtendedKeyUsage"));
}

/*
* Return the list of certificate policies
*/
Vector!( string ) X509_Certificate::policies() const
{
	return lookup_oids(subject.get("X509v3.CertificatePolicies"));
}

string X509_Certificate::ocsp_responder() const
{
	return subject.get1("OCSP.responder", "");
}

string X509_Certificate::crl_distribution_point() const
{
	return subject.get1("CRL.DistributionPoint", "");
}

/*
* Return the authority key id
*/
Vector!( byte ) X509_Certificate::authority_key_id() const
{
	return issuer.get1_memvec("X509v3.AuthorityKeyIdentifier");
}

/*
* Return the subject key id
*/
Vector!( byte ) X509_Certificate::subject_key_id() const
{
	return subject.get1_memvec("X509v3.SubjectKeyIdentifier");
}

/*
* Return the certificate serial number
*/
Vector!( byte ) X509_Certificate::serial_number() const
{
	return subject.get1_memvec("X509.Certificate.serial");
}

/*
* Return the distinguished name of the issuer
*/
X509_DN X509_Certificate::issuer_dn() const
{
	return create_dn(issuer);
}

Vector!( byte ) X509_Certificate::raw_issuer_dn() const
{
	return issuer.get1_memvec("X509.Certificate.dn_bits");
}

/*
* Return the distinguished name of the subject
*/
X509_DN X509_Certificate::subject_dn() const
{
	return create_dn(subject);
}

Vector!( byte ) X509_Certificate::raw_subject_dn() const
{
	return subject.get1_memvec("X509.Certificate.dn_bits");
}

namespace {

bool cert_subject_dns_match(in string name,
									 const Vector!( string )& cert_names)
{
	for (size_t i = 0; i != cert_names.size(); ++i)
	{
		const string cn = cert_names[i];

		if (cn == name)
			return true;

		/*
		* Possible wildcard match. We only support the most basic form of
		* cert wildcarding ala RFC 2595
		*/
		if (cn.size() > 2 && cn[0] == '*' && cn[1] == '.' && name.size() > cn.size())
		{
			const string base = cn.substr(1, string::npos);

			if (name.compare(name.size() - base.size(), base.size(), base) == 0)
				return true;
		}
	}

	return false;
}

}

string X509_Certificate::fingerprint(in string hash_name) const
{
	Unique!HashFunction hash(get_hash(hash_name));
	hash->update(this->BER_encode());
	const auto hex_print = hex_encode(hash->flush());

	string formatted_print;

	for (size_t i = 0; i != hex_print.size(); i += 2)
	{
		formatted_print.push_back(hex_print[i]);
		formatted_print.push_back(hex_print[i+1]);

		if (i != hex_print.size() - 2)
			formatted_print.push_back(':');
	}

	return formatted_print;
}

bool X509_Certificate::matches_dns_name(in string name) const
{
	if (name == "")
		return false;

	if (cert_subject_dns_match(name, subject_info("DNS")))
		return true;

	if (cert_subject_dns_match(name, subject_info("Name")))
		return true;

	return false;
}

/*
* Compare two certificates for equality
*/
bool X509_Certificate::operator==(in X509_Certificate other) const
{
	return (sig == other.sig &&
			  sig_algo == other.sig_algo &&
			  self_signed == other.self_signed &&
			  issuer == other.issuer &&
			  subject == other.subject);
}

bool X509_Certificate::operator<(in X509_Certificate other) const
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

/*
* X.509 Certificate Comparison
*/
bool operator!=(in X509_Certificate cert1, const X509_Certificate& cert2)
{
	return !(cert1 == cert2);
}

string X509_Certificate::to_string() const
{
	string[] dn_fields = { "Name",
										 "Email",
										 "Organization",
										 "Organizational Unit",
										 "Locality",
										 "State",
										 "Country",
										 "IP",
										 "DNS",
										 "URI",
										 "PKIX.XMPPAddr",
										 null };

	std::ostringstream output;

	for (size_t i = 0; dn_fields[i]; ++i)
	{
		const Vector!( string ) vals = this->subject_info(dn_fields[i]);

		if (vals.empty())
			continue;

		output << "Subject " << dn_fields[i] << ":";
		for (size_t j = 0; j != vals.size(); ++j)
			output << " " << vals[j];
		output << "";
	}

	for (size_t i = 0; dn_fields[i]; ++i)
	{
		const Vector!( string ) vals = this->issuer_info(dn_fields[i]);

		if (vals.empty())
			continue;

		output << "Issuer " << dn_fields[i] << ":";
		for (size_t j = 0; j != vals.size(); ++j)
			output << " " << vals[j];
		output << "";
	}

	output << "Version: " << this->x509_version() << "";

	output << "Not valid before: " << this->start_time() << "";
	output << "Not valid after: " << this->end_time() << "";

	output << "Constraints:";
	Key_Constraints constraints = this->constraints();
	if (constraints == NO_CONSTRAINTS)
		output << " None";
	else
	{
		if (constraints & DIGITAL_SIGNATURE)
			output << "	Digital Signature";
		if (constraints & NON_REPUDIATION)
			output << "	Non-Repuidation";
		if (constraints & KEY_ENCIPHERMENT)
			output << "	Key Encipherment";
		if (constraints & DATA_ENCIPHERMENT)
			output << "	Data Encipherment";
		if (constraints & KEY_AGREEMENT)
			output << "	Key Agreement";
		if (constraints & KEY_CERT_SIGN)
			output << "	Cert Sign";
		if (constraints & CRL_SIGN)
			output << "	CRL Sign";
	}

	Vector!( string ) policies = this->policies();
	if (!policies.empty())
	{
		output << "Policies: " << "";
		for (size_t i = 0; i != policies.size(); i++)
			output << "	" << policies[i] << "";
	}

	Vector!( string ) ex_constraints = this->ex_constraints();
	if (!ex_constraints.empty())
	{
		output << "Extended Constraints:";
		for (size_t i = 0; i != ex_constraints.size(); i++)
			output << "	" << ex_constraints[i] << "";
	}

	if (ocsp_responder() != "")
		output << "OCSP responder " << ocsp_responder() << "";
	if (crl_distribution_point() != "")
		output << "CRL " << crl_distribution_point() << "";

	output << "Signature algorithm: " <<
		OIDS::lookup(this->signature_algorithm().oid) << "";

	output << "Serial number: " << hex_encode(this->serial_number()) << "";

	if (this->authority_key_id().size())
	  output << "Authority keyid: " << hex_encode(this->authority_key_id()) << "";

	if (this->subject_key_id().size())
	  output << "Subject keyid: " << hex_encode(this->subject_key_id()) << "";

	Unique!X509_PublicKey pubkey(this->subject_public_key());
	output << "Public Key:" << X509::PEM_encode(*pubkey);

	return output.str();
}

/*
* Create and populate a X509_DN
*/
X509_DN create_dn(in Data_Store info)
{
	auto names = info.search_for(
		[](in string key, in string)
	{
			return (key.find("X520.") != string::npos);
	});

	X509_DN dn;

	for (auto i = names.begin(); i != names.end(); ++i)
		dn.add_attribute(i->first, i->second);

	return dn;
}

/*
* Create and populate an AlternativeName
*/
AlternativeName create_alt_name(in Data_Store info)
{
	auto names = info.search_for(
		[](in string key, in string)
	{
			return (key == "RFC822" ||
					  key == "DNS" ||
					  key == "URI" ||
					  key == "IP");
	});

	AlternativeName alt_name;

	for (auto i = names.begin(); i != names.end(); ++i)
		alt_name.add_attribute(i->first, i->second);

	return alt_name;
}

}
