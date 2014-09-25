/*
* ASN.1 Attribute
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_ASN1_ATTRIBUTE_H__

#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <vector>
/**
* Attribute
*/
class Attribute : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder& to) const;
		void decode_from(class BER_Decoder& from);

		OID oid;
		std::vector<byte> parameters;

		Attribute() {}
		Attribute(const OID&, in Array!byte);
		Attribute(in string, in Array!byte);
};