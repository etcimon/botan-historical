/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.alg_id;

import botan.utils.types;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oid_lookup.oids;
import string;

alias Algorithm_Identifier = FreeListRef!Algorithm_Identifier_Impl;

/**
* Algorithm Identifier
*/
final class Algorithm_Identifier_Impl : ASN1_Object
{
public:
	typedef bool Encoding_Option;
	enum : Encoding_Option { USE_NULL_PARAM }

	/*
	* DER encode an Algorithm_Identifier
	*/
	void encode_into(DER_Encoder codec) const
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.encode(oid)
				.raw_bytes(parameters)
				.end_cons();
	}

	/*
	* Decode a BER encoded Algorithm_Identifier
	*/
	void decode_from(BER_Decoder codec)
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.decode(oid)
				.raw_bytes(parameters)
				.end_cons();
	}

	this() {}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in OID, Encoding_Option) {
		__gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		oid = alg_id;
		
		if (option == USE_NULL_PARAM)
			parameters += Pair!(const ubyte*, size_t)(DER_NULL, (DER_NULL).sizeof);
	}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in string, Encoding_Option) {
		__gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		oid = oids.lookup(alg_id);
		
		if (option == USE_NULL_PARAM)
			parameters += Pair!(const ubyte*, size_t)(DER_NULL, (DER_NULL).sizeof);
	}
	
	/*
	* Create an Algorithm_Identifier
	*/
	this(in OID alg_id, in Vector!ubyte param)
	{
		oid = alg_id;
		parameters = param;
	}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in string, in Vector!ubyte) {
		oid = oids.lookup(alg_id);
		parameters = param;
	}

	/*
	* Compare two Algorithm_Identifiers
	*/
	bool opEquals(const ref Algorithm_Identifier a2)
	{
		if (oid != a2.oid)
			return false;
		if (parameters != a2.parameters)
			return false;
		return true;
	}

	/*
	* Compare two Algorithm_Identifiers
	*/
	bool opCmp(const ref Algorithm_Identifier a2)
	{
		return !(this == a2);
	}

	OID oid;
	Vector!ubyte parameters;
}