/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.alg_id;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;

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
    override void encodeInto(ref DEREncoder codec) const
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
    this(OID alg_id, EncodingOption option) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = alg_id;
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. 2];
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(string alg_id, EncodingOption option) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = OIDS.lookup(alg_id);
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. 2];
    }
    
    /*
    * Create an AlgorithmIdentifier
    */
    this(OID alg_id, ref Vector!ubyte param)
    {
        m_oid = alg_id;
        m_parameters = Array!ubyte(param[]);
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(in string alg_id, ref Vector!ubyte param) {
        m_oid = OIDS.lookup(alg_id);
		m_parameters = Array!ubyte(param[]);
    }

    /*
     * Make a copy of another AlgorithmIdentifier
     */
    this(const ref AlgorithmIdentifier other) {
        m_oid = OID(other.m_oid);
		m_parameters = Array!ubyte(other.m_parameters[]);
    }

    /*
    * Compare two AlgorithmIdentifiers
    */
    bool opEquals(in AlgorithmIdentifier a2) const
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
    int opCmp(in AlgorithmIdentifier a2) const
    {
        if (this == a2) return 0;
        else return -1;
    }

    @property OID oid() const {
        return *cast(OID*) &m_oid;
    }

    @property Array!ubyte parameters() const {
        return *cast(Array!ubyte*) &m_parameters;
    }

    @property void oid(OID oid) {
        m_oid = oid;
    }

    @property void parameters(ref Vector!ubyte param) {
		m_parameters = Array!ubyte(param[]);
    }

private:
    OID m_oid;
    Array!ubyte m_parameters;
}