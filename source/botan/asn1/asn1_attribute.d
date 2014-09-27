/*
* Attribute
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.asn1_attribute;
import botan.der_enc;
import botan.ber_dec;
import botan.oids;
/*
* Create an Attribute
*/
Attribute::Attribute(in OID attr_oid, in Vector!byte attr_value)
{
	oid = attr_oid;
	parameters = attr_value;
}

/*
* Create an Attribute
*/
Attribute::Attribute(in string attr_oid,
							in Vector!byte attr_value)
{
	oid = OIDS::lookup(attr_oid);
	parameters = attr_value;
}

/*
* DER encode a Attribute
*/
void Attribute::encode_into(DER_Encoder codec) const
{
	codec.start_cons(SEQUENCE)
		.encode(oid)
		.start_cons(SET)
			.raw_bytes(parameters)
		.end_cons()
	.end_cons();
}

/*
* Decode a BER encoded Attribute
*/
void Attribute::decode_from(BER_Decoder codec)
{
	codec.start_cons(SEQUENCE)
		.decode(oid)
		.start_cons(SET)
			.raw_bytes(parameters)
		.end_cons()
	.end_cons();
}

}
