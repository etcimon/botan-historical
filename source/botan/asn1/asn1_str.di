/*
* ASN.1 string type
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_ASN1_STRING_H__

#include <botan/asn1_obj.h>
/**
* Simple String
*/
class ASN1_String : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		string value() const;
		string iso_8859() const;

		ASN1_Tag tagging() const;

		ASN1_String(in string = "");
		ASN1_String(in string, ASN1_Tag);
	private:
		string iso_8859_str;
		ASN1_Tag tag;
};