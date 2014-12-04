/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509path;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.ocsp;
import botan.http_util;
import botan.utils.parsing;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.asn1.asn1_time;
import std.algorithm;
import std.datetime;
import botan.utils.types;
import std.container.rbtree;
version(Have_vibe_d) {
    import vibe.core.concurrency;
}
else {
    import std.concurrency;
}
import botan.cert.x509.cert_status;
import botan.cert.x509.x509cert;
import botan.cert.x509.certstor;

/**
* Specifies restrictions on the PKIX path validation
*/
struct PathValidationRestrictions
{
public:
    /**
    * @param require_rev = if true, revocation information is required
    * @param minimum_key_strength = is the minimum strength (in terms of
    *          operations, eg 80 means 2^80) of a signature. Signatures
    *          weaker than this are rejected. If more than 80, SHA-1
    *          signatures are also rejected.
    */
    this(bool require_rev = false, size_t key_strength = 80, bool ocsp_all = false) 
    {
        m_require_revocation_information = require_rev;
        m_ocsp_all_intermediates = ocsp_all;
        m_minimum_key_strength = key_strength;

        if (key_strength <= 80)
            m_trusted_hashes.insert("SHA-160");
        
        m_trusted_hashes.insert("SHA-224");
        m_trusted_hashes.insert("SHA-256");
        m_trusted_hashes.insert("SHA-384");
        m_trusted_hashes.insert("SHA-512");
    }

    /**
    * @param require_rev = if true, revocation information is required
    * @param minimum_key_strength = is the minimum strength (in terms of
    *          operations, eg 80 means 2^80) of a signature. Signatures
    *          weaker than this are rejected.
    * @param trusted_hashes = a set of trusted hashes. Any signatures
    *          created using a hash other than one of these will be
    *          rejected.
    */
    this(bool require_rev, 
         size_t minimum_key_strength, 
         bool ocsp_all_intermediates, 
         in RedBlackTree!string trusted_hashes) 
    {
        m_require_revocation_information = require_rev;
        m_ocsp_all_intermediates = ocsp_all_intermediates;
        m_trusted_hashes = trusted_hashes;
        m_minimum_key_strength = minimum_key_strength;
    }

    bool requireRevocationInformation() const
    { return m_require_revocation_information; }

    bool ocspAllIntermediates() const
    { return m_ocsp_all_intermediates; }

    RedBlackTree!string trustedHashes() const
    { return m_trusted_hashes; }

    size_t minimumKeyStrength() const
    { return m_minimum_key_strength; }

private:
    bool m_require_revocation_information;
    bool m_ocsp_all_intermediates;
    RedBlackTree!string m_trusted_hashes;
    size_t m_minimum_key_strength;
}

/**
* Represents the result of a PKIX path validation
*/
struct PathValidationResult
{
public:
    typedef Certificate_Status_Code Code;

    /**
    * @return the set of hash functions you are implicitly
    * trusting by trusting this result.
    */
    RedBlackTree!string trustedHashes() const
    {
        RedBlackTree!string hashes;
        foreach (cert_path; m_cert_path[])
            hashes.insert(cert_path.hashUsedForSignature());
        return hashes;
    }

    /**
    * @return the trust root of the validation
    */
    X509Certificate trustRoot() const
    {
        import std.range : back;
        return m_cert_path[].back;
    }

    /**
    * @return the full path from subject to trust root
    */
    Vector!X509Certificate certPath() const { return m_cert_path; }

    /**
    * @return true iff the validation was succesful
    */
    bool successfulValidation() const
    {
        if (result() == Certificate_Status_Code.VERIFIED ||
            result() == Certificate_Status_Code.OCSP_RESPONSE_GOOD)
            return true;
        return false;
    }

    /**
    * @return overall validation result code
    */
    CertificateStatusCode result() const { return m_overall; }

    /**
    * Return a set of status codes for each certificate in the chain
    */
    Vector!(  RedBlackTree!Certificate_Status_Code ) allStatuses() const
    { return m_all_status; }

    /**
    * @return string representation of the validation result
    */
    string resultString() const
    {
        return statusString(result());
    }


    static string statusString(CertificateStatusCode code)
    {
        switch(code)
        {
            case Certificate_Status_Code.VERIFIED:
                return "Verified";
            case Certificate_Status_Code.OCSP_RESPONSE_GOOD:
                return "OCSP response good";
            case Certificate_Status_Code.NO_REVOCATION_DATA:
                return "No revocation data";
            case Certificate_Status_Code.SIGNATURE_METHOD_TOO_WEAK:
                return "Signature method too weak";
            case Certificate_Status_Code.UNTRUSTED_HASH:
                return "Untrusted hash";
                
            case Certificate_Status_Code.CERT_NOT_YET_VALID:
                return "Certificate is not yet valid";
            case Certificate_Status_Code.CERT_HAS_EXPIRED:
                return "Certificate has expired";
            case Certificate_Status_Code.OCSP_NOT_YET_VALID:
                return "OCSP is not yet valid";
            case Certificate_Status_Code.OCSP_HAS_EXPIRED:
                return "OCSP has expired";
            case Certificate_Status_Code.CRL_NOT_YET_VALID:
                return "CRL is not yet valid";
            case Certificate_Status_Code.CRL_HAS_EXPIRED:
                return "CRL has expired";
                
            case Certificate_Status_Code.CERT_ISSUER_NOT_FOUND:
                return "Certificate issuer not found";
            case Certificate_Status_Code.CANNOT_ESTABLISH_TRUST:
                return "Cannot establish trust";
                
            case Certificate_Status_Code.POLICY_ERROR:
                return "TLSPolicy error";
            case Certificate_Status_Code.INVALID_USAGE:
                return "Invalid usage";
            case Certificate_Status_Code.CERT_CHAIN_TOO_LONG:
                return "Certificate chain too long";
            case Certificate_Status_Code.CA_CERT_NOT_FOR_CERT_ISSUER:
                return "CA certificate not allowed to issue certs";
            case Certificate_Status_Code.CA_CERT_NOT_FOR_CRL_ISSUER:
                return "CA certificate not allowed to issue CRLs";
            case Certificate_Status_Code.OCSP_CERT_NOT_LISTED:
                return "OCSP cert not listed";
            case Certificate_Status_Code.OCSP_BAD_STATUS:
                return "OCSP bad status";
                
            case Certificate_Status_Code.CERT_IS_REVOKED:
                return "Certificate is revoked";
            case Certificate_Status_Code.CRL_BAD_SIGNATURE:
                return "CRL bad signature";
            case Certificate_Status_Code.SIGNATURE_ERROR:
                return "Signature error";
            default:
                return "Unknown error";
        }
    }

    this(Vector!(  RedBlackTree!Certificate_Status_Code ) status,
                           Vector!X509Certificate cert_chainput)
    {
        m_overall = Certificate_Status_Code.VERIFIED;
        m_all_status = status;
        m_cert_path = cert_chainput;
        // take the "worst" error as overall
        foreach (s; m_all_status[])
        {
            if (!s.empty)
            {
                auto worst = s.back;
                // Leave OCSP confirmations on cert-level status only
                if (worst != Certificate_Status_Code.OCSP_RESPONSE_GOOD)
                    m_overall = worst;
            }
        }
    }


    this(CertificateStatusCode status)  { m_overall = status; }

private:
    Certificate_Status_Code m_overall;
    Vector!( RedBlackTree!Certificate_Status_Code ) m_all_status;
    Vector!X509Certificate m_cert_path;
}

/**
* PKIX Path Validation
*/
PathValidationResult 
    x509PathValidate(in Vector!X509Certificate end_certs,
                       in PathValidationRestrictions restrictions,
                       in Vector!CertificateStore certstores)
{
    if (end_certs.empty)
        throw new InvalidArgument("x509PathValidate called with no subjects");
    
    Vector!X509Certificate cert_path;
    cert_path.pushBack(end_certs[0]);
    
    auto extra = scoped!CertificateStoreOverlay(end_certs);
    
    // iterate until we reach a root or cannot find the issuer
    while (!cert_path.back().isSelfSigned())
    {
        const X509Certificate cert = findIssuingCert(cert_path.back(), extra, certstores);
        if (!cert)
            return Path_Validation_Result(Certificate_Status_Code.CERT_ISSUER_NOT_FOUND);
        
        cert_path.pushBack(*cert);
    }
    
    return Path_Validation_Result(checkChain(cert_path, restrictions, certstores),
                                  std.algorithm.move(cert_path));
}


/**
* PKIX Path Validation
*/
PathValidationResult x509PathValidate(in X509Certificate end_cert,
                                          in PathValidationRestrictions restrictions,
                                          in Vector!CertificateStore certstores)
{
    Vector!X509Certificate certs;
    certs.pushBack(end_cert);
    return x509PathValidate(certs, restrictions, certstores);
}

/**
* PKIX Path Validation
*/

PathValidationResult x509PathValidate(in X509Certificate end_cert,
                                          in PathValidationRestrictions restrictions,
                                          in CertificateStore store)
{
    Vector!X509Certificate certs;
    certs.pushBack(end_cert);
    
    Vector!CertificateStore certstores;
    certstores.pushBack(&store);
    
    return x509PathValidate(certs, restrictions, certstores);
}
/**
* PKIX Path Validation
*/
PathValidationResult x509PathValidate(in Vector!X509Certificate end_certs,
                                          in PathValidationRestrictions restrictions,
                                          in CertificateStore store)
{
    Vector!CertificateStore certstores;
    certstores.pushBack(&store);
    
    return x509PathValidate(end_certs, restrictions, certstores);
}

X509Certificate findIssuingCert(in X509Certificate cert,
                                         ref CertificateStore end_certs, 
                                         in Vector!CertificateStore certstores) const
{
    const X509DN issuer_dn = cert.issuerDn();
    const Vector!ubyte auth_key_id = cert.authorityKeyId();
    
    if (const X509Certificate cert = end_certs.findCert(issuer_dn, auth_key_id))
        return cert;
    
    foreach (certstore; certstores)
    {
        if (const X509Certificate cert = certstore.findCert(issuer_dn, auth_key_id))
            return cert;
    }
    
    return null;
}

X509CRL findCrlsFor(in X509Certificate cert,
                              const ref Vector!CertificateStore certstores) const
{
    foreach (certstore; certstores)
    {
        if (const X509CRL crl = certstore.findCrlFor(cert))
            return crl;
    }

    /// todo: use crl distribution point and download the CRL
    version(none) {
        /*
        const string crl_url = cert.crlDistributionPoint();
        if (crl_url != "")
        {
        std::cout << "Downloading CRL " << crl_url << "";
            auto http = HTTP::GET_sync(crl_url);
            
        std::cout << http.status_message() << "";
            
            http.throw_unless_ok();
            // check the mime type
            
            auto crl = X509CRL(http.body());
            
            return crl;
        }*/
    }
    
    return null;
}

Vector!( RedBlackTree!Certificate_Status_Code )
    checkChain(in Vector!X509Certificate cert_path,
                in PathValidationRestrictions restrictions,
                in Vector!CertificateStore certstores)
{
    const RedBlackTree!string trusted_hashes = restrictions.trustedHashes();
    
    const bool self_signed_ee_cert = (cert_path.length == 1);
    
    X509Time current_time = X509Time(Clock.currTime());
    
    Vector!( Tid ) ocsp_responses;
    
    Vector!( RedBlackTree!Certificate_Status_Code ) cert_status = Vector!( Vector!Certificate_Status_Code )( cert_path.length );
    
    foreach (size_t i; 0 .. cert_path.length)
    {
        auto status = &cert_status[i];
        
        const bool at_self_signed_root = (i == cert_path.length - 1);
        
        const X509Certificate subject = cert_path[i];
        
        const X509Certificate issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];
        
        const CertificateStore trusted = certstores[0]; // fixme
        
        if (i == 0 || restrictions.ocspAllIntermediates()) {
            version(Have_vibe_d)
                ocsp_responses.pushBack(runTask(&onlineCheck, issuer, subject, trusted));
            else
                ocsp_responses.pushBack(spawn(&onlineCheck, issuer, subject, trusted));

        }
        // Check all certs for valid time range
        if (current_time < X509Time(subject.startTime()))
            status.insert(Certificate_Status_Code.CERT_NOT_YET_VALID);
        
        if (current_time > X509Time(subject.endTime()))
            status.insert(Certificate_Status_Code.CERT_HAS_EXPIRED);
        
        // Check issuer constraints
        
        // Don't require CA bit set on self-signed end entity cert
        if (!issuer.isCACert() && !self_signed_ee_cert)
            status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CERT_ISSUER);
        
        if (issuer.pathLimit() < i)
            status.insert(Certificate_Status_Code.CERT_CHAIN_TOO_LONG);
        
        Unique!PublicKey issuer_key = issuer.subjectPublicKey();
        
        if (subject.checkSignature(*issuer_key) == false)
            status.insert(Certificate_Status_Code.SIGNATURE_ERROR);
        
        if (issuer_key.estimatedStrength() < restrictions.minimumKeyStrength())
            status.insert(Certificate_Status_Code.SIGNATURE_METHOD_TOO_WEAK);
        
        // Allow untrusted hashes on self-signed roots
        if (!trusted_hashes.empty && !at_self_signed_root)
        {
            if (subject.hashUsedForSignature() !in trusted_hashes)
                status.insert(Certificate_Status_Code.UNTRUSTED_HASH);
        }
    }
    
    foreach (size_t i; 0 .. cert_path.length - 1)
    {

        auto status = &cert_status[i];
        
        const X509Certificate subject = cert_path[i];
        const X509Certificate ca = cert_path[i+1];
        
        if (i < ocsp_responses.length)
        {
            try
            {
                OCSPResponse ocsp = ocsp_responses[i].receiveOnly!(OCSPResponse)();
                
                auto ocsp_status = ocsp.statusFor(ca, subject);
                
                status.insert(ocsp_status);
                
                //std::cout << "OCSP status: " << statusString(ocsp_status) << "\n";
                
                // Either way we have a definitive answer, no need to check CRLs
                if (ocsp_status == Certificate_Status_Code.CERT_IS_REVOKED)
                    return cert_status;
                else if (ocsp_status == Certificate_Status_Code.OCSP_RESPONSE_GOOD)
                    continue;
            }
            catch(Exception e)
            {
                //std::cout << "OCSP error: " << e.msg << "";
            }
        }
        
        const X509CRL crl_p = findCrlsFor(subject, certstores);
        
        if (!crl_p)
        {
            if (restrictions.requireRevocationInformation())
                status.insert(Certificate_Status_Code.NO_REVOCATION_DATA);
            continue;
        }
        
        const X509CRL crl = *crl_p;
        
        if (!ca.allowedUsage(CRL_SIGN))
            status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CRL_ISSUER);
        
        if (current_time < X509Time(crl.thisUpdate()))
            status.insert(Certificate_Status_Code.CRL_NOT_YET_VALID);
        
        if (current_time > X509Time(crl.nextUpdate()))
            status.insert(Certificate_Status_Code.CRL_HAS_EXPIRED);
        
        if (crl.checkSignature(ca.subjectPublicKey()) == false)
            status.insert(Certificate_Status_Code.CRL_BAD_SIGNATURE);
        
        if (crl.isRevoked(subject))
            status.insert(Certificate_Status_Code.CERT_IS_REVOKED);
    }
    
    if (self_signed_ee_cert)
        cert_status.back().insert(Certificate_Status_Code.CANNOT_ESTABLISH_TRUST);
    
    return cert_status;
}