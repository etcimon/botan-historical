/*
* Common ASN.1 Objects
* (C) 1999-2007 Jack Lloyd
*	  2007 Yves Jerschow
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_obj.h>
#include <botan/asn1_str.h>
#include <botan/asn1_oid.h>
#include <map>
/**
* Alternative Name
*/
class AlternativeName : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		std::multimap<string, string> contents() const;

		void add_attribute(in string, in string);
		std::multimap<string, string> get_attributes() const;

		void add_othername(in OID, in string, ASN1_Tag);
		std::multimap<OID, ASN1_String> get_othernames() const;

		bool has_items() const;

		AlternativeName(in string = "", in string = "",
							 in string = "", in string = "");
	private:
		std::multimap<string, string> alt_info;
		std::multimap<OID, ASN1_String> othernames;
};