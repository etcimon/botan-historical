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
import botan.asn1.oids;
// import string;

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
				.encode(m_oid)
				.raw_bytes(m_parameters)
				.end_cons();
	}

	/*
	* Decode a BER encoded Algorithm_Identifier
	*/
	void decode_from(BER_Decoder codec)
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
				.decode(m_oid)
				.raw_bytes(m_parameters)
				.end_cons();
	}

	this() {}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in OID, Encoding_Option) {
		__gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		m_oid = alg_id;
		
		if (option == USE_NULL_PARAM)
			m_parameters ~= DER_NULL.ptr[0 .. $];
	}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in string, Encoding_Option) {
		__gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		m_oid = OIDS.lookup(alg_id);
		
		if (option == USE_NULL_PARAM)
			m_parameters ~= DER_NULL.ptr[0 .. $];
	}
	
	/*
	* Create an Algorithm_Identifier
	*/
	this(in OID alg_id, in Vector!ubyte param)
	{
		m_oid = alg_id;
		m_parameters = param;
	}

	/*
	* Create an Algorithm_Identifier
	*/
	this(in string, in Vector!ubyte) {
		m_oid = OIDS.lookup(alg_id);
		m_parameters = param;
	}

	/*
	* Compare two Algorithm_Identifiers
	*/
	bool opEquals(in Algorithm_Identifier a2)
	{
		if (m_oid != a2.m_oid)
			return false;
		if (m_parameters != a2.m_parameters)
			return false;
		return true;
	}

	/*
	* Compare two Algorithm_Identifiers
	*/
	bool opCmp(in Algorithm_Identifier a2)
	{
		return !(this == a2);
	}

	OID m_oid;
	Vector!ubyte m_parameters;
}