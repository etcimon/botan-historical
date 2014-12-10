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

alias AlgorithmIdentifier = FreeListRef!AlgorithmIdentifierImpl;

/**
* Algorithm Identifier
*/
final class AlgorithmIdentifierImpl : ASN1Object
{
public:
    alias EncodingOption = bool;
    enum : EncodingOption { USE_NULL_PARAM }

    /*
    * DER encode an AlgorithmIdentifier
    */
    override void encodeInto(DEREncoder codec) const
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .encode(m_oid)
                .rawBytes(m_parameters)
                .endCons();
    }

    /*
    * Decode a BER encoded AlgorithmIdentifier
    */
    override void decodeFrom(BERDecoder codec)
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .decode(m_oid)
                .rawBytes(m_parameters)
                .endCons();
    }

    this() {}

    /*
    * Create an AlgorithmIdentifier
    */
    this(in OID, EncodingOption) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = alg_id;
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. $];
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(in string, EncodingOption) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = OIDS.lookup(alg_id);
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. $];
    }
    
    /*
    * Create an AlgorithmIdentifier
    */
    this(in OID alg_id, in Vector!ubyte param)
    {
        m_oid = alg_id;
        m_parameters = param;
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(in string, in Vector!ubyte) {
        m_oid = OIDS.lookup(alg_id);
        m_parameters = param;
    }

    /*
    * Compare two AlgorithmIdentifiers
    */
    bool opEquals(in AlgorithmIdentifier a2)
    {
        if (m_oid != a2.m_oid)
            return false;
        if (m_parameters != a2.m_parameters)
            return false;
        return true;
    }

    /*
    * Compare two AlgorithmIdentifiers
    */
    bool opCmp(in AlgorithmIdentifier a2)
    {
        return !(this == a2);
    }

    OID m_oid;
    Vector!ubyte m_parameters;
}