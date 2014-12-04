/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_crl;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509_obj;
import botan.cert.x509.crl_ent;
import botan.cert.x509.x509_ext;
import botan.cert.x509.x509cert;
import botan.asn1.x509_dn;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.math.bigint.bigint;
import botan.asn1.oids;
import botan.asn1.asn1_time;
import botan.utils.types;

alias X509CRL = FreeListRef!X509CRLImpl;

/**
* This class represents X.509 Certificate Revocation Lists (CRLs).
*/
final class X509CRLImpl : X509Object
{
public:
    /**
    * This class represents CRL related errors.
    */
    class X509CRLError : Exception
    {
        this(in string error) {
            super("X509CRL: " ~ error);
        }
    }

    /**
    * Check if this particular certificate is listed in the CRL
    */
    bool isRevoked(in X509Certificate cert) const
    {
        /*
        If the cert wasn't issued by the CRL issuer, it's possible the cert
        is revoked, but not by this CRL. Maybe throw new an exception instead?
        */
        if (cert.issuerDn() != issuerDn())
            return false;
        
        Vector!ubyte crl_akid = authorityKeyId();
        Vector!ubyte cert_akid = cert.authorityKeyId();
        
        if (!crl_akid.empty && !cert_akid.empty)
            if (crl_akid != cert_akid)
                return false;
        
        Vector!ubyte cert_serial = cert.serialNumber();
        
        bool is_revoked = false;
        
        foreach (const revoked; m_revoked)
        {
            if (cert_serial == revoked.serialNumber())
            {
                if (revoked.reasonCode() == CRL_Code.REMOVE_FROM_CRL)
                    is_revoked = false;
                else
                    is_revoked = true;
            }
        }
        
        return is_revoked;
    }


    /**
    * Get the entries of this CRL in the form of a vector.
    * @return vector containing the entries of this CRL.
    */
    Vector!CRLEntry getRevoked() const
    {
        return m_revoked;
    }

    /**
    * Get the issuer DN of this CRL.
    * @return CRLs issuer DN
    */
    X509DN issuerDn() const
    {
        return create_dn(m_info);
    }


    /**
    * Get the AuthorityKeyIdentifier of this CRL.
    * @return this CRLs AuthorityKeyIdentifier
    */
    Vector!ubyte authorityKeyId() const
    {
        return m_info.get1Memvec("X509v3.AuthorityKeyIdentifier");
    }

    /**
    * Get the serial number of this CRL.
    * @return CRLs serial number
    */
    uint crlNumber() const
    {
        return m_info.get1Uint("X509v3.CRLNumber");
    }

    /**
    * Get the CRL's thisUpdate value.
    * @return CRLs thisUpdate
    */
    X509Time thisUpdate() const
    {
        return m_info.get1("X509.CRL.start");
    }

    /**
    * Get the CRL's nextUpdate value.
    * @return CRLs nextdUpdate
    */
    X509Time nextUpdate() const
    {
        return m_info.get1("X509.CRL.end");
    }

    /**
    * Construct a CRL from a data source.
    * @param source = the data source providing the DER or PEM encoded CRL.
    * @param throw_on_unknown_critical_ = should we throw new an exception
    * if an unknown CRL extension marked as critical is encountered.
    */
    this(DataSource input, bool throw_on_unknown_critical_ = false)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
        super(input, "X509 CRL/CRL");
        doDecode();
    }

    /**
    * Construct a CRL from a file containing the DER or PEM encoded CRL.
    * @param filename = the name of the CRL file
    * @param throw_on_unknown_critical_ = should we throw new an exception
    * if an unknown CRL extension marked as critical is encountered.
    */
    this(in string filename,
                bool throw_on_unknown_critical_ = false)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
        super(input, "CRL/X509 CRL");
        doDecode();
    }

    /**
    * Construct a CRL from a binary vector
    * @param vec = the binary (DER) representation of the CRL
    * @param throw_on_unknown_critical_ = should we throw new an exception
    * if an unknown CRL extension marked as critical is encountered.
    */
    this(in Vector!ubyte vec,
                bool throw_on_unknown_critical_ = false)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
        super(input, "CRL/X509 CRL");
        doDecode();
    }

private:

    /*
    * Decode the TBSCertList data
    */
    void forceDecode()
    {
        BERDecoder tbs_crl = BERDecoder(tbs_bits);
        
        size_t _version;
        tbs_crl.decodeOptional(_version, INTEGER, ASN1Tag.UNIVERSAL);
        
        if (_version != 0 && _version != 1)
            throw new X509CRLError("Unknown X.509 CRL version " ~
                                     to!string(_version+1));
        
        AlgorithmIdentifier sig_algo_inner;
        tbs_crl.decode(sig_algo_inner);
        
        if (sig_algo != sig_algo_inner)
            throw new X509CRLError("Algorithm identifier mismatch");
        
        X509DN dn_issuer;
        tbs_crl.decode(dn_issuer);
        m_info.add(dn_issuer.contents());
        
        X509Time start, end;
        tbs_crl.decode(start).decode(end);
        m_info.add("X509.CRL.start", start.readableString());
        m_info.add("X509.CRL.end", end.readableString());
        
        BERObject next = tbs_crl.getNextObject();
        
        if (next.type_tag == ASN1Tag.SEQUENCE && next.class_tag == ASN1Tag.CONSTRUCTED)
        {
            BERDecoder cert_list = BERDecoder(next.value);
            
            while (cert_list.moreItems())
            {
                CRLEntry entry = CRLEntry(m_throw_on_unknown_critical);
                cert_list.decode(entry);
                m_revoked.pushBack(entry);
            }
            next = tbs_crl.getNextObject();
        }
        
        if (next.type_tag == 0 &&
            next.class_tag == ASN1Tag(ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
        {
            BERDecoder crl_options = BERDecoder(next.value);
            
            X509Extensions extensions = X509Extensions(m_throw_on_unknown_critical);
            
            crl_options.decode(extensions).verifyEnd();
            
            extensions.contentsTo(m_info, m_info);
            
            next = tbs_crl.getNextObject();
        }
        
        if (next.type_tag != ASN1Tag.NO_OBJECT)
            throw new X509CRLError("Unknown tag in CRL");
        
        tbs_crl.verifyEnd();
    }


    bool m_throw_on_unknown_critical;
    Vector!CRLEntry m_revoked;
    DataStore m_info;
}