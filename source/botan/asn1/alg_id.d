/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.alg_id;

import botan.asn1_obj;
import botan.asn1_oid;
import botan.der_enc;
import botan.ber_dec;
import botan.asn1.oid_lookup.oids;

import string;

class DER_Encoder;
class BER_Decoder;

/**
* Algorithm Identifier
*/
class AlgorithmIdentifier : public ASN1_Object
{
public:
	enum Encoding_Option { USE_NULL_PARAM };

	void encode_into(DER_Encoder) const;
	void decode_from(BER_Decoder);

	this() {}
	this(in OID, Encoding_Option);
	this(in string, Encoding_Option);

	this(in OID, in Vector!byte);
	this(in string, in Vector!byte);

	OID oid;
	Vector!byte parameters;
};

/*
* Comparison Operations
*/
bool operator==(in AlgorithmIdentifier,
								  const AlgorithmIdentifier&);
bool operator!=(in AlgorithmIdentifier,
								  const AlgorithmIdentifier&);


/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(in OID alg_id,
                                         in Vector!byte param)
{
	oid = alg_id;
	parameters = param;
}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(in string alg_id,
                                         in Vector!byte param)
{
	oid = oids.lookup(alg_id);
	parameters = param;
}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(in OID alg_id,
                                         Encoding_Option option)
{
	imutable byte[] DER_NULL = { 0x05, 0x00 };
	
	oid = alg_id;
	
	if (option == USE_NULL_PARAM)
		parameters += Pair!(const byte*, size_t)(DER_NULL, sizeof(DER_NULL));
}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(in string alg_id,
                                         Encoding_Option option)
{
	imutable byte[] DER_NULL = { 0x05, 0x00 };
	
	oid = oids.lookup(alg_id);
	
	if (option == USE_NULL_PARAM)
		parameters += Pair!(const byte*, size_t)(DER_NULL, sizeof(DER_NULL));
}

/*
* Compare two AlgorithmIdentifiers
*/
bool operator==(in AlgorithmIdentifier a1, const AlgorithmIdentifier& a2)
{
	if (a1.oid != a2.oid)
		return false;
	if (a1.parameters != a2.parameters)
		return false;
	return true;
}

/*
* Compare two AlgorithmIdentifiers
*/
bool operator!=(in AlgorithmIdentifier a1, const AlgorithmIdentifier& a2)
{
	return !(a1 == a2);
}

/*
* DER encode an AlgorithmIdentifier
*/
void AlgorithmIdentifier::encode_into(DER_Encoder codec) const
{
	codec.start_cons(SEQUENCE)
		.encode(oid)
			.raw_bytes(parameters)
			.end_cons();
}

/*
* Decode a BER encoded AlgorithmIdentifier
*/
void AlgorithmIdentifier::decode_from(BER_Decoder codec)
{
	codec.start_cons(SEQUENCE)
		.decode(oid)
			.raw_bytes(parameters)
			.end_cons();
}

}
