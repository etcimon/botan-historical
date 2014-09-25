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

		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		AlgorithmIdentifier() {}
		AlgorithmIdentifier(const OID&, Encoding_Option);
		AlgorithmIdentifier(in string, Encoding_Option);

		AlgorithmIdentifier(const OID&, in Array!byte);
		AlgorithmIdentifier(in string, in Array!byte);

		OID oid;
		std::vector<byte> parameters;
};

/*
* Comparison Operations
*/
bool operator==(const AlgorithmIdentifier&,
								  const AlgorithmIdentifier&);
bool operator!=(const AlgorithmIdentifier&,
								  const AlgorithmIdentifier&);