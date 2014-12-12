/*
* ASN.1 Attribute
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.asn1.asn1_attribute;

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.utils.types;

alias Attribute = FreeListRef!AttributeImpl;

/**
* Attribute
*/
final class AttributeImpl : ASN1Object
{
public:
    /*
    * Create an Attribute
    */
    this(OID attr_oid, Vector!ubyte attr_value)
    {
        oid = attr_oid;
        parameters = attr_value;
    }
    
    /*
    * Create an Attribute
    */
    this(in string attr_oid, Vector!ubyte attr_value)
    {
        oid = OIDS.lookup(attr_oid);
        parameters = attr_value;
    }
    
    /*
    * DER encode a Attribute
    */
	override void encodeInto(DEREncoderImpl codec) const
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .encode(oid)
                .startCons(ASN1Tag.SET)
                .rawBytes(parameters)
                .endCons()
                .endCons();
    }
    
    /*
    * Decode a BER encoded Attribute
    */
	override void decodeFrom(BERDecoderImpl codec)
    {
        codec.startCons(ASN1Tag.SEQUENCE)
            .decode(oid)
                .startCons(ASN1Tag.SET)
                .rawBytes(parameters)
                .endCons()
                .endCons();
    }

    OID oid;
    Vector!ubyte parameters;

}


