/*
* OCSP subtypes
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.ocsp_types;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509cert;
import botan.asn1.asn1_time;
import botan.math.bigint.bigint;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.cert.x509.x509_ext;
import botan.libstate.lookup;
import botan.hash.hash;
import botan.asn1.oids;
import botan.utils.types;

alias CertID = FreeListRef!CertID_Impl;

final class CertID_Impl : ASN1_Object
{
public:
    this() {}

    this(in X509_Certificate issuer,
         const X509_Certificate subject)
    {
        /*
        In practice it seems some responders, including, notably,
        ocsp.verisign.com, will reject anything but SHA-1 here
        */
        Unique!HashFunction hash = get_hash("SHA-160");
        
        m_hash_id = Algorithm_Identifier(hash.name, Algorithm_Identifier.USE_NULL_PARAM);
        m_issuer_key_hash = unlock(hash.process(extract_key_bitstr(issuer)));
        m_issuer_dn_hash = unlock(hash.process(subject.raw_issuer_dn()));
        m_subject_serial = BigInt.decode(subject.serial_number());
    }

    bool is_id_for(in X509_Certificate issuer,
                   const X509_Certificate subject) const
    {
        try
        {
            if (BigInt.decode(subject.serial_number()) != m_subject_serial)
                return false;
            
            Unique!HashFunction hash = get_hash(OIDS.lookup(m_hash_id.oid));
            
            if (m_issuer_dn_hash != unlock(hash.process(subject.raw_issuer_dn())))
                return false;
            
            if (m_issuer_key_hash != unlock(hash.process(extract_key_bitstr(issuer))))
                return false;
        }
        catch
        {
            return false;
        }
        
        return true;
    }

    override void encode_into(DER_Encoder to) const
    {
        to.start_cons(ASN1_Tag.SEQUENCE)
                .encode(m_hash_id)
                .encode(m_issuer_dn_hash, ASN1_Tag.OCTET_STRING)
                .encode(m_issuer_key_hash, ASN1_Tag.OCTET_STRING)
                .encode(m_subject_serial)
                .end_cons();
    }


    void decode_from(BER_Decoder from)
    {
        from.start_cons(ASN1_Tag.SEQUENCE)
                .decode(m_hash_id)
                .decode(m_issuer_dn_hash, ASN1_Tag.OCTET_STRING)
                .decode(m_issuer_key_hash, ASN1_Tag.OCTET_STRING)
                .decode(m_subject_serial)
                .end_cons();
        
    }

private:
    Vector!ubyte extract_key_bitstr(in X509_Certificate cert) const
    {
        const auto key_bits = cert.subject_public_key_bits();
        
        Algorithm_Identifier public_key_algid;
        Vector!ubyte public_key_bitstr;
        
        BER_Decoder(key_bits)
                .decode(public_key_algid)
                .decode(public_key_bitstr, ASN1_Tag.BIT_STRING);
        
        return public_key_bitstr;
    }

    Algorithm_Identifier m_hash_id;
    Vector!ubyte m_issuer_dn_hash;
    Vector!ubyte m_issuer_key_hash;
    BigInt m_subject_serial;
}

alias SingleResponse = FreeListRef!SingleResponse_Impl;

final class SingleResponse_Impl : ASN1_Object
{
public:
    const CertID certid() const { return m_certid; }

    size_t cert_status() const { return m_cert_status; }

    X509_Time this_update() const { return m_thisupdate; }

    X509_Time next_update() const { return m_nextupdate; }

    override void encode_into(DER_Encoder) const
    {
        throw new Exception("Not implemented (SingleResponse::encode_into)");
    }

    override void decode_from(BER_Decoder from)
    {
        BER_Object cert_status;
        Extensions extensions;
        
        from.start_cons(ASN1_Tag.SEQUENCE)
                .decode(m_certid)
                .get_next(cert_status)
                .decode(m_thisupdate)
                .decode_optional(m_nextupdate, ASN1_Tag(0),
                                 ASN1_Tag(ASN1_Tag.CONTEXT_SPECIFIC | ASN1_Tag.CONSTRUCTED))
                .decode_optional(extensions, ASN1_Tag(1),
                                 ASN1_Tag(ASN1_Tag.CONTEXT_SPECIFIC | ASN1_Tag.CONSTRUCTED))
                .end_cons();
        
        m_cert_status = cert_status.type_tag;
    }

private:
    CertID m_certid;
    size_t m_cert_status = 2; // unknown
    X509_Time m_thisupdate;
    X509_Time m_nextupdate;
}