/*
* X.509 Distinguished Name
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <botan/asn1_str.h>
#include <map>
#include <iosfwd>
/**
* Distinguished Name
*/
class X509_DN : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder) const;
		void decode_from(class BER_Decoder);

		std::multimap<OID, string> get_attributes() const;
		Vector!( string ) get_attribute(in string) const;

		std::multimap<string, string> contents() const;

		void add_attribute(in string, in string);
		void add_attribute(in OID, in string);

		static string deref_info_field(in string);

		Vector!( byte ) get_bits() const;

		X509_DN();
		X509_DN(in std::multimap<OID, string>);
		X509_DN(in std::multimap<string, string>);
	private:
		std::multimap<OID, ASN1_String> dn_info;
		Vector!( byte ) dn_bits;
};

bool operator==(in X509_DN, const X509_DN&);
bool operator!=(in X509_DN, const X509_DN&);
bool operator<(in X509_DN, const X509_DN&);

std::ostream& operator<<(std::ostream& out, const X509_DN& dn);