/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <string>
/**
* Algorithm Identifier
*/
class AlgorithmIdentifier : public ASN1_Object
{
	public:
		enum Encoding_Option { USE_NULL_PARAM };

		void encode_into(class DER_Encoder) const;
		void decode_from(class BER_Decoder);

		AlgorithmIdentifier() {}
		AlgorithmIdentifier(in OID, Encoding_Option);
		AlgorithmIdentifier(in string, Encoding_Option);

		AlgorithmIdentifier(in OID, in Vector!byte);
		AlgorithmIdentifier(in string, in Vector!byte);

		OID oid;
		Vector!( byte ) parameters;
};

/*
* Comparison Operations
*/
bool operator==(in AlgorithmIdentifier,
								  const AlgorithmIdentifier&);
bool operator!=(in AlgorithmIdentifier,
								  const AlgorithmIdentifier&);