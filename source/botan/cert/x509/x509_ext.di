/*
* X.509 Certificate Extensions
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.datastor;
import botan.crl_ent;
/**
* X.509 Certificate Extension
*/
class Certificate_Extension
{
	public:
		/**
		* @return OID representing this extension
		*/
		OID oid_of() const;

		/**
		* Make a copy of this extension
		* @return copy of this
		*/
		abstract Certificate_Extension* copy() const;

		/*
		* Add the contents of this extension into the information
		* for the subject and/or issuer, as necessary.
		* @param subject the subject info
		* @param issuer the issuer info
		*/
		abstract void contents_to(Data_Store& subject,
										 Data_Store& issuer) const;

		/*
		* @return specific OID name
		*/
		abstract string oid_name() const;

		~this() {}
	package:
		friend class Extensions;
		abstract bool should_encode() const { return true; }
		abstract Vector!ubyte encode_inner() const;
		abstract void decode_inner(in Vector!ubyte);
};

/**
* X.509 Certificate Extension List
*/
class Extensions : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		void contents_to(Data_Store&, Data_Store&) const;

		void add(Certificate_Extension* extn, bool critical = false);

		Extensions& operator=(in Extensions);

		Extensions(in Extensions);
		Extensions(bool st = true) : m_throw_on_unknown_critical(st) {}
		~this();
	private:
		static Certificate_Extension* get_extension(in OID);

		Vector!( Pair!(Certificate_Extension*, bool)  ) extensions;
		bool m_throw_on_unknown_critical;
};

namespace Cert_Extension {

static const size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
class Basic_Constraints : public Certificate_Extension
{
	public:
		Basic_Constraints* copy() const
		{ return new Basic_Constraints(is_ca, path_limit); }

		Basic_Constraints(bool ca = false, size_t limit = 0) :
			is_ca(ca), path_limit(limit) {}

		bool get_is_ca() const { return is_ca; }
		size_t get_path_limit() const;
	private:
		string oid_name() const { return "X509v3.BasicConstraints"; }

		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		bool is_ca;
		size_t path_limit;
};

/**
* Key Usage Constraints Extension
*/
class Key_Usage : public Certificate_Extension
{
	public:
		Key_Usage* copy() const { return new Key_Usage(constraints); }

		Key_Usage(Key_Constraints c = NO_CONSTRAINTS) : constraints(c) {}

		Key_Constraints get_constraints() const { return constraints; }
	private:
		string oid_name() const { return "X509v3.KeyUsage"; }

		bool should_encode() const { return (constraints != NO_CONSTRAINTS); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Key_Constraints constraints;
};

/**
* Subject Key Identifier Extension
*/
class Subject_Key_ID : public Certificate_Extension
{
	public:
		Subject_Key_ID* copy() const { return new Subject_Key_ID(key_id); }

		Subject_Key_ID() {}
		Subject_Key_ID(in Vector!ubyte);

		Vector!ubyte get_key_id() const { return key_id; }
	private:
		string oid_name() const { return "X509v3.SubjectKeyIdentifier"; }

		bool should_encode() const { return (key_id.size() > 0); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Vector!ubyte key_id;
};

/**
* Authority Key Identifier Extension
*/
class Authority_Key_ID : public Certificate_Extension
{
	public:
		Authority_Key_ID* copy() const { return new Authority_Key_ID(key_id); }

		Authority_Key_ID() {}
		Authority_Key_ID(in Vector!ubyte k) : key_id(k) {}

		Vector!ubyte get_key_id() const { return key_id; }
	private:
		string oid_name() const { return "X509v3.AuthorityKeyIdentifier"; }

		bool should_encode() const { return (key_id.size() > 0); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Vector!ubyte key_id;
};

/**
* Alternative Name Extension Base Class
*/
class Alternative_Name : public Certificate_Extension
{
	public:
		AlternativeName get_alt_name() const { return alt_name; }

	package:
		Alternative_Name(in AlternativeName, in string oid_name);

		Alternative_Name(in string, in string);
	private:
		string oid_name() const { return oid_name_str; }

		bool should_encode() const { return alt_name.has_items(); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		string oid_name_str;
		AlternativeName alt_name;
};

/**
* Subject Alternative Name Extension
*/
class Subject_Alternative_Name : public Alternative_Name
{
	public:
		Subject_Alternative_Name* copy() const
		{ return new Subject_Alternative_Name(get_alt_name()); }

		Subject_Alternative_Name(in AlternativeName = AlternativeName());
};

/**
* Issuer Alternative Name Extension
*/
class Issuer_Alternative_Name : public Alternative_Name
{
	public:
		Issuer_Alternative_Name* copy() const
		{ return new Issuer_Alternative_Name(get_alt_name()); }

		Issuer_Alternative_Name(in AlternativeName = AlternativeName());
};

/**
* Extended Key Usage Extension
*/
class Extended_Key_Usage : public Certificate_Extension
{
	public:
		Extended_Key_Usage* copy() const { return new Extended_Key_Usage(oids); }

		Extended_Key_Usage() {}
		Extended_Key_Usage(in Vector!( OID ) o) : oids(o) {}

		Vector!( OID ) get_oids() const { return oids; }
	private:
		string oid_name() const { return "X509v3.ExtendedKeyUsage"; }

		bool should_encode() const { return (oids.size() > 0); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Vector!( OID ) oids;
};

/**
* Certificate Policies Extension
*/
class Certificate_Policies : public Certificate_Extension
{
	public:
		Certificate_Policies* copy() const
		{ return new Certificate_Policies(oids); }

		Certificate_Policies() {}
		Certificate_Policies(in Vector!( OID ) o) : oids(o) {}

		Vector!( OID ) get_oids() const { return oids; }
	private:
		string oid_name() const { return "X509v3.CertificatePolicies"; }

		bool should_encode() const { return (oids.size() > 0); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Vector!( OID ) oids;
};

class Authority_Information_Access : public Certificate_Extension
{
	public:
		Authority_Information_Access* copy() const
		{ return new Authority_Information_Access(m_ocsp_responder); }

		Authority_Information_Access() {}

		Authority_Information_Access(in string ocsp) :
			m_ocsp_responder(ocsp) {}

	private:
		string oid_name() const { return "PKIX.AuthorityInformationAccess"; }

		bool should_encode() const { return (m_ocsp_responder != ""); }

		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);

		void contents_to(Data_Store&, Data_Store&) const;

		string m_ocsp_responder;
};

/**
* CRL Number Extension
*/
class CRL_Number : public Certificate_Extension
{
	public:
		CRL_Number* copy() const;

		CRL_Number() : has_value(false), crl_number(0) {}
		CRL_Number(size_t n) : has_value(true), crl_number(n) {}

		size_t get_crl_number() const;
	private:
		string oid_name() const { return "X509v3.CRLNumber"; }

		bool should_encode() const { return has_value; }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		bool has_value;
		size_t crl_number;
};

/**
* CRL Entry Reason Code Extension
*/
class CRL_ReasonCode : public Certificate_Extension
{
	public:
		CRL_ReasonCode* copy() const { return new CRL_ReasonCode(reason); }

		CRL_ReasonCode(CRL_Code r = UNSPECIFIED) : reason(r) {}

		CRL_Code get_reason() const { return reason; }
	private:
		string oid_name() const { return "X509v3.ReasonCode"; }

		bool should_encode() const { return (reason != UNSPECIFIED); }
		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		CRL_Code reason;
};

/**
* CRL Distribution Points Extension
*/
class CRL_Distribution_Points : public Certificate_Extension
{
	public:
		class Distribution_Point : public ASN1_Object
		{
			public:
				void encode_into(class DER_Encoder&) const;
				void decode_from(class BER_Decoder&);

				const AlternativeName& point() const { return m_point; }
			private:
				AlternativeName m_point;
		};

		CRL_Distribution_Points* copy() const
		{ return new CRL_Distribution_Points(m_distribution_points); }

		CRL_Distribution_Points() {}

		CRL_Distribution_Points(in Vector!( Distribution_Point ) points) :
			m_distribution_points(points) {}

		Vector!( Distribution_Point ) distribution_points() const
		{ return m_distribution_points; }

	private:
		string oid_name() const { return "X509v3.CRLDistributionPoints"; }

		bool should_encode() const { return !m_distribution_points.empty(); }

		Vector!ubyte encode_inner() const;
		void decode_inner(in Vector!ubyte);
		void contents_to(Data_Store&, Data_Store&) const;

		Vector!( Distribution_Point ) m_distribution_points;
};

}