/*
* ASN.1 Attribute
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.asn1.asn1_attribute;

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oid_lookup.oids;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import vector;

class DER_Encoder;
class BER_Decoder;

/**
* Attribute
*/
class Attribute : public ASN1_Object
{
public:

	/*
	* Create an Attribute
	*/
	this(in OID attr_oid, in Vector!ubyte attr_value)
	{
		oid = attr_oid;
		parameters = attr_value;
	}
	
	/*
	* Create an Attribute
	*/
	this(in string attr_oid,
	     in Vector!ubyte attr_value)
	{
		oid = oids.lookup(attr_oid);
		parameters = attr_value;
	}
	
	/*
	* DER encode a Attribute
	*/
	void encode_into(DER_Encoder codec) const
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.encode(oid)
				.start_cons(ASN1_Tag.SET)
				.raw_bytes(parameters)
				.end_cons()
				.end_cons();
	}
	
	/*
	* Decode a BER encoded Attribute
	*/
	void decode_from(BER_Decoder codec)
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.decode(oid)
				.start_cons(ASN1_Tag.SET)
				.raw_bytes(parameters)
				.end_cons()
				.end_cons();
	}

	OID oid;
	Vector!ubyte parameters;

	this() {}
};


