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

alias AlgorithmIdentifier = FreeListRef!AlgorithmIdentifierImpl;

/**
* Algorithm Identifier
*/
class AlgorithmIdentifierImpl : ASN1_Object
{
public:
	typedef bool Encoding_Option;
	enum : Encoding_Option { USE_NULL_PARAM };

	/*
	* DER encode an AlgorithmIdentifier
	*/
	void encode_into(DER_Encoder codec) const
	{
		codec.start_cons(ASN1_Tag.SEQUENCE)
			.encode(oid)
				.raw_bytes(parameters)
				.end_cons();
	}

	/*
	* Decode a BER encoded AlgorithmIdentifier
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
	* Create an AlgorithmIdentifier
	*/
	this(in OID, Encoding_Option) {
		immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		oid = alg_id;
		
		if (option == USE_NULL_PARAM)
			parameters += Pair!(const ubyte*, size_t)(DER_NULL, sizeof(DER_NULL));
	}

	/*
	* Create an AlgorithmIdentifier
	*/
	this(in string, Encoding_Option) {
		immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
		
		oid = oids.lookup(alg_id);
		
		if (option == USE_NULL_PARAM)
			parameters += Pair!(const ubyte*, size_t)(DER_NULL, sizeof(DER_NULL));
	}
	
	/*
	* Create an AlgorithmIdentifier
	*/
	this(in OID alg_id, in Vector!ubyte param)
	{
		oid = alg_id;
		parameters = param;
	}

	/*
	* Create an AlgorithmIdentifier
	*/
	this(in string, in Vector!ubyte) {
		oid = oids.lookup(alg_id);
		parameters = param;
	}

	/*
	* Compare two AlgorithmIdentifiers
	*/
	bool opEquals(const ref AlgorithmIdentifier a2)
	{
		if (oid != a2.oid)
			return false;
		if (parameters != a2.parameters)
			return false;
		return true;
	}

	/*
	* Compare two AlgorithmIdentifiers
	*/
	bool opCmp(const ref AlgorithmIdentifier a2)
	{
		return !(this == a2);
	}

	OID oid;
	Vector!ubyte parameters;
};