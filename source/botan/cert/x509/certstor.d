/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.certstor;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.utils.types;
import std.file;

/**
* Certificate Store Interface
*/
class CertificateStore
{
public:
    ~this() {}

    /**
    * Subject DN and (optionally) key identifier
    */
    abstract X509Certificate findCert(in X509DN subject_dn, in Vector!ubyte key_id) const;

    abstract X509CRL findCrlFor(in X509Certificate subject) const
    {
        return null;
    }


    bool certificateKnown(in X509Certificate cert) const
    {
        return find_cert(cert.subjectDn(), cert.subjectKeyId());
    }

    // remove this (used by TLS_Server)
    abstract Vector!X509DN allSubjects() const;
}

/**
* In Memory Certificate Store
*/
final class CertificateStoreInMemory : Certificate_Store
{
public:
    /**
    * Attempt to parse all files in dir (including subdirectories)
    * as certificates. Ignores errors.
    */
    this(in string dir)
    {
        if (dir == "")
            return;
        foreach(string name; dirEntries(dir, SpanMode.breadth)) {
            if (isFile(name))
                m_certs.pushBack(X509Certificate(name));
        }
    }

    this() {}

    void addCertificate(in X509Certificate cert)
    {
        foreach (const cert_stored; m_certs[])
        {
            if (cert_stored == cert)
                return;
        }
        
        m_certs.pushBack(cert);
    }

    Vector!X509DN allSubjects() const
    {
        Vector!X509DN subjects;
        foreach (ref cert; m_certs)
            subjects.pushBack(cert.subjectDn());
        return subjects;
    }

    X509Certificate findCert(in X509DN subject_dn, in Vector!ubyte key_id) const
    {
        return cert_search(subject_dn, key_id, m_certs);
    }

    void addCrl(in X509CRL crl)
    {
        X509DN crl_issuer = crl.issuerDn();
        
        foreach (crl_stored; m_crls[])
        {
            // Found an update of a previously existing one; replace it
            if (crl_stored.issuerDn() == crl_issuer)
            {
                if (crl_stored.thisUpdate() <= crl.thisUpdate())
                    crl_stored = crl;
                return;
            }
        }
        
        // Totally new CRL, add to the list
        m_crls.pushBack(crl);
    }

    X509CRL findCrlFor(in X509Certificate subject) const
    {
        const Vector!ubyte key_id = subject.authorityKeyId();
        
        foreach (const crl; m_crls)
        {
            // Only compare key ids if set in both call and in the CRL
            if (key_id.length)
            {
                Vector!ubyte akid = crl.authorityKeyId();
                
                if (akid.length && akid != key_id) // no match
                    continue;
            }
            
            if (crl.issuerDn() == subject.issuerDn())
                return crl;
        }
        
        return null;
    }

private:
    // TODO: Add indexing on the DN and key id to avoid linear search
    Vector!X509Certificate m_certs;
    Vector!X509CRL m_crls;
}

final class CertificateStoreOverlay : Certificate_Store
{
public:
    this(in Vector!X509Certificate certs)
    {
        m_certs = certs;
    }

    Vector!X509DN allSubjects() const
    {
        Vector!X509DN subjects;
        foreach (cert; m_certs)
            subjects.pushBack(cert.subjectDn());
        return subjects;
    }

    X509Certificate findCert(in X509DN subject_dn, in Vector!ubyte key_id) const
    {
        return cert_search(subject_dn, key_id, m_certs);
    }
private:
    const Vector!X509Certificate m_certs;
}

X509Certificate certSearch(in X509DN subject_dn, 
                                   in Vector!ubyte key_id, 
                                   in Vector!X509Certificate certs) const
{
    foreach (const cert; certs[])
    {
        // Only compare key ids if set in both call and in the cert
        if (key_id.length)
        {
            Vector!ubyte skid = cert.subjectKeyId();
            
            if (skid.length && skid != key_id) // no match
                continue;
        }
        
        if (cert.subjectDn() == subject_dn)
            return cert;
    }
    
    return null;
}