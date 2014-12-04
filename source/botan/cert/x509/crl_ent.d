/*
* CRL Entry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.crl_ent;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509cert;
import botan.asn1.asn1_time;
import botan.cert.x509.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.asn1.oids;
import botan.utils.types;

alias CRLEntry = FreeListRef!CRLEntryImpl;

/**
* X.509v2 CRL Reason Code.
*/
enum CRLCode {
    UNSPECIFIED             = 0,
    KEY_COMPROMISE          = 1,
    CA_COMPROMISE           = 2,
    AFFILIATION_CHANGED     = 3,
    SUPERSEDED              = 4,
    CESSATION_OF_OPERATION  = 5,
    CERTIFICATE_HOLD        = 6,
    REMOVE_FROM_CRL         = 8,
    PRIVLEDGE_WITHDRAWN     = 9,
    AA_COMPROMISE           = 10,

    DELETE_CRL_ENTRY        = 0xFF00,
    OCSP_GOOD               = 0xFF01,
    OCSP_UNKNOWN            = 0xFF02
}

/**
* This class represents CRL entries
*/
final class CRLEntryImpl : ASN1Object
{
public:
    /*
    * DER encode a CRLEntry
    */
    void encodeInto(DEREncoder to_) const
    {
        X509Extensions extensions;
        
        extensions.add(new CRLReasonCode(reason));
        
        to_.startCons(ASN1Tag.SEQUENCE)
                .encode(BigInt.decode(serial))
                .encode(m_time)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(extensions)
                .endCons()
                .endCons();
    }
    

    /*
    * Decode a BER encoded CRLEntry
    */
    void decodeFrom(BERDecoder source)
    {
        BigInt serial_number_bn;
        m_reason = CRL_Code.UNSPECIFIED;
        
        BERDecoder entry = source.startCons(ASN1Tag.SEQUENCE);
        
        entry.decode(serial_number_bn).decode(m_time);
        
        if (entry.moreItems())
        {
            X509Extensions extensions = X509Extensions(m_throw_on_unknown_critical);
            entry.decode(extensions);
            DataStore info;
            extensions.contentsTo(info, info);
            m_reason = CRL_Code(info.get1Uint("X509v3.CRLReasonCode"));
        }
        
        entry.endCons();
        
        serial = BigInt.encode(serial_number_bn);
    }

    /**
    * Get the serial number of the certificate associated with this entry.
    * @return certificate's serial number
    */
    Vector!ubyte serialNumber() const { return m_serial; }

    /**
    * Get the revocation date of the certificate associated with this entry
    * @return certificate's revocation date
    */
    X509Time expireTime() const { return m_time; }

    /**
    * Get the entries reason code
    * @return reason code
    */
    CRLCode reasonCode() const { return m_reason; }

    /**
    * Construct an empty CRL entry.
    */
    this(bool throw_on_unknown_critical_extension)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_extension;
        m_reason = CRL_Code.UNSPECIFIED;
    }

    /**
    * Construct an CRL entry.
    * @param cert = the certificate to revoke
    * @param reason = the reason code to set in the entry
    */
    this(in X509Certificate cert, CRLCode why = CRL_Code.UNSPECIFIED)
    {
        m_throw_on_unknown_critical = false;
        m_serial = cert.serialNumber();
        m_time = X509Time(Clock.currTime());
        m_reason = why;
    }

    /*
    * Compare two CRL_Entrys for equality
    */
    bool opEquals(in CRLEntry a2)
    {
        if (serialNumber() != a2.serialNumber())
            return false;
        if (expireTime() != a2.expireTime())
            return false;
        if (reasonCode() != a2.reasonCode())
            return false;
        return true;
    }

    /*
    * Compare two CRL_Entrys for inequality
    */
    bool opCmp(string op)(in CRLEntry a2)
        if (op == "!=")
    {
        return !(this == a2);
    }


private:
    bool m_throw_on_unknown_critical;
    Vector!ubyte m_serial;
    X509Time m_time;
    CRL_Code m_reason;
}