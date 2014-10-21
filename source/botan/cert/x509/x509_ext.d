/*
* X.509 Certificate Extensions
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_ext;

import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.utils.datastor.datastor;
import botan.cert.x509.crl_ent;
import botan.hash.sha160;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oid_lookup.oids;
import botan.utils.charset;
import botan.utils.bit_ops;
import std.algorithm;

/**
* X.509 Certificate Extension
*/
class Certificate_Extension
{
public:
	/**
	* @return OID representing this extension
	*/
	OID oid_of() const
	{
		return oids.lookup(oid_name());
	}

	/**
	* Make a copy of this extension
	* @return copy of this
	*/
	abstract Certificate_Extension copy() const;

	/*
	* Add the contents of this extension into the information
	* for the subject and/or issuer, as necessary.
	* @param subject the subject info
	* @param issuer the issuer info
	*/
	abstract void contents_to(ref Data_Store subject,
							  ref Data_Store issuer) const;

	/*
	* @return specific OID name
	*/
	abstract string oid_name() const;

	~this() {}
package:
	abstract bool should_encode() const { return true; }
	abstract Vector!ubyte encode_inner() const;
	abstract void decode_inner(in Vector!ubyte);
};

/**
* X.509 Certificate Extension List
*/
class Extensions : ASN1_Object
{
public:

	void encode_into(DER_Encoder to) const
	{
		for (size_t i = 0; i != extensions.length; ++i)
		{
			const Certificate_Extension ext = extensions[i].first;
			const bool is_critical = extensions[i].second;
			
			const bool should_encode = ext.should_encode();
			
			if (should_encode)
			{
				to_object.start_cons(ASN1_Tag.SEQUENCE)
					.encode(ext.oid_of())
						.encode_optional(is_critical, false)
						.encode(ext.encode_inner(), ASN1_Tag.OCTET_STRING)
						.end_cons();
			}
		}
	}

	void decode_from(BER_Decoder from_source)
	{
		for (size_t i = 0; i != extensions.length; ++i)
			delete extensions[i].first;
		extensions.clear();
		
		BER_Decoder sequence = from_source.start_cons(ASN1_Tag.SEQUENCE);
		
		while(sequence.more_items())
		{
			OID oid;
			Vector!ubyte value;
			bool critical;
			
			sequence.start_cons(ASN1_Tag.SEQUENCE)
				.decode(oid)
					.decode_optional(critical, BOOLEAN, ASN1_Tag.UNIVERSAL, false)
					.decode(value, ASN1_Tag.OCTET_STRING)
					.verify_end()
					.end_cons();
			
			Certificate_Extension ext = get_extension(oid);
			
			if (!ext && critical && m_throw_on_unknown_critical)
				throw new Decoding_Error("Encountered unknown X.509 extension marked "
				                         "as critical; OID = " ~ oid.as_string());
			
			if (ext)
			{
				try
				{
					ext.decode_inner(value);
				}
				catch(Exception e)
				{
					throw new Decoding_Error("Exception while decoding extension " ~
					                         oid.as_string() ~ ": " ~ e.what());
				}
				
				extensions.push_back(Pair(ext, critical));
			}
		}
		
		sequence.verify_end();
	}

	void contents_to(ref Data_Store subject_info,
	                 ref Data_Store issuer_info) const
	{
		for (size_t i = 0; i != extensions.length; ++i)
			extensions[i].first.contents_to(subject_info, issuer_info);
	}

	void add(Certificate_Extension extn, bool critical)
	{
		extensions.push_back(Pair(extn, critical));
	}

	Extensions opAssign(in Extensions other)
	{
		for (size_t i = 0; i != extensions.length; ++i)
			delete extensions[i].first;
		extensions.clear();
		
		for (size_t i = 0; i != other.extensions.length; ++i)
			extensions.push_back(
				Pair(other.extensions[i].first.copy(),
			other.extensions[i].second));
		
		return this;
	}

	this(in Extensions ext) {
		this = ext;
	}

	this(bool st = true) { m_throw_on_unknown_critical = st; }
	~this()
	{
		for (size_t i = 0; i != extensions.length; ++i)
			delete extensions[i].first;
	}

private:

	/*
	* List of X.509 Certificate Extensions
	*/
	Certificate_Extension get_extension(in OID oid)
	{
		string X509_EXTENSION(T)(string NAME, T t) {
			return "if (oids.name_of(oid, " ~ NAME ~ ")) return new x509_ext. ~ " ~ T.stringof ~ "();";
		}
		
		mixin( X509_EXTENSION("X509v3.KeyUsage", Key_Usage) );
		mixin( X509_EXTENSION("X509v3.BasicConstraints", Basic_Constraints) );
		mixin( X509_EXTENSION("X509v3.SubjectKeyIdentifier", Subject_Key_ID) );
		mixin( X509_EXTENSION("X509v3.AuthorityKeyIdentifier", Authority_Key_ID) );
		mixin( X509_EXTENSION("X509v3.ExtendedKeyUsage", Extended_Key_Usage) );
		mixin( X509_EXTENSION("X509v3.IssuerAlternativeName", Issuer_Alternative_Name) );
		mixin( X509_EXTENSION("X509v3.SubjectAlternativeName", Subject_Alternative_Name) );
		mixin( X509_EXTENSION("X509v3.CertificatePolicies", Certificate_Policies) );
		mixin( X509_EXTENSION("X509v3.CRLDistributionPoints", CRL_Distribution_Points) );
		mixin( X509_EXTENSION("PKIX.AuthorityInformationAccess", Authority_Information_Access) );
		mixin( X509_EXTENSION("X509v3.CRLNumber", CRL_Number) );
		mixin( X509_EXTENSION("X509v3.ReasonCode", CRL_ReasonCode) );
		
		return null;
	}


	Vector!( Pair!(Certificate_Extension, bool)  ) extensions;
	bool m_throw_on_unknown_critical;
};

static const size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
class Basic_Constraints : Certificate_Extension
{
public:
	Basic_Constraints copy() const
	{ return new Basic_Constraints(is_ca, path_limit); }

	this(bool ca = false, size_t limit = 0)
	{
		is_ca = ca;
		path_limit = limit; 
	}

	bool get_is_ca() const { return is_ca; }
	/*
	* Checked accessor for the path_limit member
	*/
	size_t get_path_limit() const
	{
		if (!is_ca)
			throw new Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
		return path_limit;
	}

private:
	string oid_name() const { return "X509v3.BasicConstraints"; }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode_if (is_ca,
				            DER_Encoder()
				            .encode(is_ca)
				            .encode_optional(path_limit, NO_CERT_PATH_LIMIT)
				            )
				.end_cons()
				.get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode_optional(is_ca, BOOLEAN, ASN1_Tag.UNIVERSAL, false)
				.decode_optional(path_limit, INTEGER, ASN1_Tag.UNIVERSAL, NO_CERT_PATH_LIMIT)
				.verify_end()
				.end_cons();
		
		if (is_ca == false)
			path_limit = 0;
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store subject, ref Data_Store) const
	{
		subject.add("X509v3.BasicConstraints.is_ca", (is_ca ? 1 : 0));
		subject.add("X509v3.BasicConstraints.path_constraint", path_limit);
	}

	bool is_ca;
	size_t path_limit;
};

/**
* Key Usage Constraints Extension
*/
class Key_Usage : Certificate_Extension
{
public:
	Key_Usage copy() const { return new Key_Usage(constraints); }

	this(Key_Constraints c = Key_Constraints.NO_CONSTRAINTS) { constraints = c; }

	Key_Constraints get_constraints() const { return constraints; }
private:
	string oid_name() const { return "X509v3.KeyUsage"; }

	bool should_encode() const { return (constraints != Key_Constraints.NO_CONSTRAINTS); }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		if (constraints == Key_Constraints.NO_CONSTRAINTS)
			throw new Encoding_Error("Cannot encode zero usage constraints");
		
		const size_t unused_bits = low_bit(constraints) - 1;
		
		Vector!ubyte der;
		der.push_back(ASN1_Tag.BIT_STRING);
		der.push_back(2 + ((unused_bits < 8) ? 1 : 0));
		der.push_back(unused_bits % 8);
		der.push_back((constraints >> 8) & 0xFF);
		if (constraints & 0xFF)
			der.push_back(constraints & 0xFF);
		
		return der;
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder ber(input);
		
		BER_Object obj = ber.get_next_object();
		
		if (obj.type_tag != ASN1_Tag.BIT_STRING || obj.class_tag != ASN1_Tag.UNIVERSAL)
			throw new BER_Bad_Tag("Bad tag for usage constraint",
			                      obj.type_tag, obj.class_tag);
		
		if (obj.value.length != 2 && obj.value.length != 3)
			throw new BER_Decoding_Error("Bad size for BITSTRING in usage constraint");
		
		if (obj.value[0] >= 8)
			throw new BER_Decoding_Error("Invalid unused bits in usage constraint");
		
		obj.value[obj.value.length-1] &= (0xFF << obj.value[0]);
		
		ushort usage = 0;
		for (size_t i = 1; i != obj.value.length; ++i)
			usage = (obj.value[i] << 8) | usage;
		
		constraints = Key_Constraints(usage);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store subject, ref Data_Store) const
	{
		subject.add("X509v3.KeyUsage", constraints);
	}

	Key_Constraints constraints;
};

/**
* Subject Key Identifier Extension
*/
class Subject_Key_ID : Certificate_Extension
{
public:
	Subject_Key_ID copy() const { return new Subject_Key_ID(key_id); }

	this() {}
	this(in Vector!ubyte pub_key)
	{
		SHA_160 hash;
		key_id = unlock(hash.process(pub_key));
	}


	Vector!ubyte get_key_id() const { return key_id; }
private:
	string oid_name() const { return "X509v3.SubjectKeyIdentifier"; }

	bool should_encode() const { return (key_id.length > 0); }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder().encode(key_id, ASN1_Tag.OCTET_STRING).get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input).decode(key_id, ASN1_Tag.OCTET_STRING).verify_end();
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store subject, ref Data_Store) const
	{
		subject.add("X509v3.SubjectKeyIdentifier", key_id);
	}

	Vector!ubyte key_id;
};

/**
* Authority Key Identifier Extension
*/
class Authority_Key_ID : Certificate_Extension
{
public:
	Authority_Key_ID* copy() const { return new Authority_Key_ID(key_id); }

	this() {}
	this(in Vector!ubyte k) { key_id = k; }

	Vector!ubyte get_key_id() const { return key_id; }
private:
	string oid_name() const { return "X509v3.AuthorityKeyIdentifier"; }

	bool should_encode() const { return (key_id.length > 0); }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(key_id, ASN1_Tag.OCTET_STRING, ASN1_Tag(0), ASN1_Tag.CONTEXT_SPECIFIC)
				.end_cons()
				.get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode_optional_string(key_id, ASN1_Tag.OCTET_STRING, 0);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store, ref Data_Store issuer) const
	{
		if (key_id.length)
			issuer.add("X509v3.AuthorityKeyIdentifier", key_id);
	}


	Vector!ubyte key_id;
};

/**
* Alternative Name Extension Base Class
*/
class Alternative_Name : Certificate_Extension
{
public:
	AlternativeName get_alt_name() const { return alt_name; }

package:

	this(in AlternativeName alt_name,
	     in string oid_name_str)
	{
		this.alt_name = alt_name;
		this.oid_name_str = oid_name_str;
	}

private:
	string oid_name() const { return oid_name_str; }

	bool should_encode() const { return alt_name.has_items(); }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder().encode(alt_name).get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input).decode(alt_name);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store subject_info,
	                 ref Data_Store issuer_info) const
	{
		MultiMap!(string, string) contents =
			get_alt_name().contents();
		
		if (oid_name_str == "X509v3.SubjectAlternativeName")
			subject_info.add(contents);
		else if (oid_name_str == "X509v3.IssuerAlternativeName")
			issuer_info.add(contents);
		else
			throw new Internal_Error("In Alternative_Name, unknown type " ~
			                         oid_name_str);
	}

	string oid_name_str;
	AlternativeName alt_name;
};




/**
* Subject Alternative Name Extension
*/
class Subject_Alternative_Name : Alternative_Name
{
public:
	Subject_Alternative_Name copy() const
	{ return new Subject_Alternative_Name(get_alt_name()); }

	this() {}
	this(in AlternativeName name = AlternativeName()) {
		super(name, "X509v3.SubjectAlternativeName");
	}
};

/**
* Issuer Alternative Name Extension
*/
class Issuer_Alternative_Name : Alternative_Name
{
public:
	Issuer_Alternative_Name copy() const
	{ return new Issuer_Alternative_Name(get_alt_name()); }

	this(in AlternativeName name = AlternativeName()) {
		super(name, "X509v3.IssuerAlternativeName");
	}
};

/**
* Extended Key Usage Extension
*/
class Extended_Key_Usage : Certificate_Extension
{
public:
	Extended_Key_Usage copy() const { return new Extended_Key_Usage(oids); }

	this() {}
	this(in Vector!( OID ) o) : oids(o) {}

	Vector!( OID ) get_oids() const { return oids; }
private:
	string oid_name() const { return "X509v3.ExtendedKeyUsage"; }

	bool should_encode() const { return (oids.length > 0); }
	/*
* Encode the extension
*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode_list(oids)
				.end_cons()
				.get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input).decode_list(oids);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store subject, ref Data_Store) const
	{
		for (size_t i = 0; i != oids.length; ++i)
			subject.add("X509v3.ExtendedKeyUsage", oids[i].as_string());
	}

	Vector!( OID ) oids;
};

/**
* Certificate Policies Extension
*/
class Certificate_Policies : Certificate_Extension
{
public:
	Certificate_Policies copy() const
	{ return new Certificate_Policies(oids); }

	Certificate_Policies() {}
	Certificate_Policies(in Vector!( OID ) o) : oids(o) {}

	Vector!( OID ) get_oids() const { return oids; }
private:
	string oid_name() const { return "X509v3.CertificatePolicies"; }

	bool should_encode() const { return (oids.length > 0); }

	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		Vector!( Policy_Information ) policies;
		
		for (size_t i = 0; i != oids.length; ++i)
			policies.push_back(oids[i]);
		
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode_list(policies)
				.end_cons()
				.get_contents_unlocked();
	}
	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		Vector!( Policy_Information ) policies;
		
		BER_Decoder(input).decode_list(policies);
		
		oids.clear();
		for (size_t i = 0; i != policies.length; ++i)
			oids.push_back(policies[i].oid);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store info, ref Data_Store) const
	{
		for (size_t i = 0; i != oids.length; ++i)
			info.add("X509v3.CertificatePolicies", oids[i].as_string());
	}

	Vector!( OID ) oids;
};

class Authority_Information_Access : Certificate_Extension
{
public:
	Authority_Information_Access copy() const
	{ return new Authority_Information_Access(m_ocsp_responder); }

	this() {}

	this(in string ocsp) :
		m_ocsp_responder(ocsp) {}

private:
	string oid_name() const { return "PKIX.AuthorityInformationAccess"; }

	bool should_encode() const { return (m_ocsp_responder != ""); }

	Vector!ubyte encode_inner() const
	{
		ASN1_String url(m_ocsp_responder, IA5_STRING);
		
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(oids.lookup("PKIX.OCSP"))
				.add_object(ASN1_Tag(6), ASN1_Tag.CONTEXT_SPECIFIC, url.iso_8859())
				.end_cons()
				.end_cons().get_contents_unlocked();
	}

	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder ber = BER_Decoder(input).start_cons(ASN1_Tag.SEQUENCE);
		
		while(ber.more_items())
		{
			OID oid;
			
			BER_Decoder info = ber.start_cons(ASN1_Tag.SEQUENCE);
			
			info.decode(oid);
			
			if (oid == oids.lookup("PKIX.OCSP"))
			{
				BER_Object name = info.get_next_object();
				
				if (name.type_tag == 6 && name.class_tag == ASN1_Tag.CONTEXT_SPECIFIC)
				{
					m_ocsp_responder = transcode(asn1.to_string(name),
					                                     LATIN1_CHARSET,
					                                     LOCAL_CHARSET);
				}
				
			}
		}
	}



	void contents_to(ref Data_Store subject, ref Data_Store) const
	{
		if (m_ocsp_responder != "")
			subject.add("OCSP.responder", m_ocsp_responder);
	}

	string m_ocsp_responder;
};


/**
* CRL Number Extension
*/
class CRL_Number : Certificate_Extension
{
public:
	/*
	* Copy a CRL_Number extension
	*/
	CRL_Number* copy() const
	{
		if (!has_value)
			throw new Invalid_State("CRL_Number::copy: Not set");
		return new CRL_Number(crl_number);
	}


	this() { has_value = false; crl_number = 0; }
	CRL_Number(size_t n) { has_value = true; crl_number = n; }

	/*
	* Checked accessor for the crl_number member
	*/
	size_t get_crl_number() const
	{
		if (!has_value)
			throw new Invalid_State("CRL_Number::get_crl_number: Not set");
		return crl_number;
	}

private:
	string oid_name() const { return "X509v3.CRLNumber"; }

	bool should_encode() const { return has_value; }
	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder().encode(crl_number).get_contents_unlocked();
	}
	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		BER_Decoder(input).decode(crl_number);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store info, ref Data_Store) const
	{
		info.add("X509v3.CRLNumber", crl_number);
	}

	bool has_value;
	size_t crl_number;
};

/**
* CRL Entry Reason Code Extension
*/
class CRL_ReasonCode : Certificate_Extension
{
public:
	CRL_ReasonCode* copy() const { return new CRL_ReasonCode(reason); }

	this(CRL_Code r = CRL_Code.UNSPECIFIED) { reason = r; }

	CRL_Code get_reason() const { return reason; }
private:
	string oid_name() const { return "X509v3.ReasonCode"; }

	bool should_encode() const { return (reason != CRL_Code.UNSPECIFIED); }
	/*
	* Encode the extension
	*/
	Vector!ubyte encode_inner() const
	{
		return DER_Encoder()
			.encode(cast(size_t)(reason), ASN1_Tag.ENUMERATED, ASN1_Tag.UNIVERSAL)
				.get_contents_unlocked();
	}

	/*
	* Decode the extension
	*/
	void decode_inner(in Vector!ubyte input)
	{
		size_t reason_code = 0;
		BER_Decoder(input).decode(reason_code, ASN1_Tag.ENUMERATED, ASN1_Tag.UNIVERSAL);
		reason = cast(CRL_Code)(reason_code);
	}

	/*
	* Return a textual representation
	*/
	void contents_to(ref Data_Store info, ref Data_Store) const
	{
		info.add("X509v3.CRLReasonCode", reason);
	}

	CRL_Code reason;
};


/**
* CRL Distribution Points Extension
*/
class CRL_Distribution_Points : Certificate_Extension
{
public:
	class Distribution_Point : ASN1_Object
	{
	public:
		void encode_into(DER_Encoder) const
		{
			throw new Exception("CRL_Distribution_Points encoding not implemented");
		}

		void decode_from(BER_Decoder ber)
		{
			ber.start_cons(ASN1_Tag.SEQUENCE)
				.start_cons(ASN1_Tag(0), ASN1_Tag.CONTEXT_SPECIFIC)
					.decode_optional_implicit(m_point, ASN1_Tag(0),
					                          ASN1_Tag(ASN1_Tag.CONTEXT_SPECIFIC | CONSTRUCTED),
					                          ASN1_Tag.SEQUENCE, CONSTRUCTED)
					.end_cons().end_cons();
		}


		const AlternativeName point() const { return m_point; }
	private:
		AlternativeName m_point;
	};

	CRL_Distribution_Points copy() const
	{ return new CRL_Distribution_Points(m_distribution_points); }

	this() {}

	this(in Vector!( Distribution_Point ) points) { m_distribution_points = points; }

	Vector!( Distribution_Point ) distribution_points() const
	{ return m_distribution_points; }

private:
	string oid_name() const { return "X509v3.CRLDistributionPoints"; }

	bool should_encode() const { return !m_distribution_points.empty(); }

	Vector!ubyte encode_inner() const
	{
		throw new Exception("CRL_Distribution_Points encoding not implemented");
	}

	void decode_inner(in Vector!ubyte buf)
	{
		BER_Decoder(buf).decode_list(m_distribution_points).verify_end();
	}


	void contents_to(ref Data_Store info, ref Data_Store) const
	{
		for (size_t i = 0; i != m_distribution_points.length; ++i)
		{
			auto point = m_distribution_points[i].point().contents();
			
			auto uris = point.equal_range("URI");
			
			for (auto uri = uris.first; uri != uris.second; ++uri)
				info.add("CRL.DistributionPoint", uri.second);
		}
	}

	Vector!( Distribution_Point ) m_distribution_points;
};

/*
* A policy specifier
*/
class Policy_Information : ASN1_Object
{
public:
	OID oid;
	
	this() {}
	this(in OID oid_) { oid = oid_; }
	
	void encode_into(DER_Encoder codec) const
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.encode(oid)
				.end_cons();
	}
	
	void decode_from(BER_Decoder codec)
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.decode(oid)
				.discard_remaining()
				.end_cons();
	}
};
