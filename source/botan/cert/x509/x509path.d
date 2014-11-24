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
struct Path_Validation_Restrictions
{
public:
    /**
    * @param require_rev if true, revocation information is required
    * @param minimum_key_strength is the minimum strength (in terms of
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
    * @param require_rev if true, revocation information is required
    * @param minimum_key_strength is the minimum strength (in terms of
    *          operations, eg 80 means 2^80) of a signature. Signatures
    *          weaker than this are rejected.
    * @param trusted_hashes a set of trusted hashes. Any signatures
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

    bool require_revocation_information() const
    { return m_require_revocation_information; }

    bool ocsp_all_intermediates() const
    { return m_ocsp_all_intermediates; }

    const RedBlackTree!string trusted_hashes() const
    { return m_trusted_hashes; }

    size_t minimum_key_strength() const
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
struct Path_Validation_Result
{
public:
    typedef Certificate_Status_Code Code;

    /**
    * @return the set of hash functions you are implicitly
    * trusting by trusting this result.
    */
    RedBlackTree!string trusted_hashes() const
    {
        RedBlackTree!string hashes;
        foreach (cert_path; m_cert_path[])
            hashes.insert(cert_path.hash_used_for_signature());
        return hashes;
    }

    /**
    * @return the trust root of the validation
    */
    const X509_Certificate trust_root() const
    {
        import std.range : back;
        return m_cert_path[].back;
    }

    /**
    * @return the full path from subject to trust root
    */
    const Vector!X509_Certificate cert_path() const { return m_cert_path; }

    /**
    * @return true iff the validation was succesful
    */
    bool successful_validation() const
    {
        if (result() == Certificate_Status_Code.VERIFIED ||
            result() == Certificate_Status_Code.OCSP_RESPONSE_GOOD)
            return true;
        return false;
    }

    /**
    * @return overall validation result code
    */
    Certificate_Status_Code result() const { return m_overall; }

    /**
    * Return a set of status codes for each certificate in the chain
    */
    const Vector!(  RedBlackTree!Certificate_Status_Code ) all_statuses() const
    { return m_all_status; }

    /**
    * @return string representation of the validation result
    */
    string result_string() const
    {
        return status_string(result());
    }


    static string status_string(Certificate_Status_Code code)
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
                return "Policy error";
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
                           Vector!X509_Certificate cert_chainput)
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


    this(Certificate_Status_Code status)  { m_overall = status; }

private:
    Certificate_Status_Code m_overall;
    Vector!( RedBlackTree!Certificate_Status_Code ) m_all_status;
    Vector!X509_Certificate m_cert_path;
}

/**
* PKIX Path Validation
*/
Path_Validation_Result 
    x509_path_validate(in Vector!X509_Certificate end_certs,
                       in Path_Validation_Restrictions restrictions,
                       in Vector!Certificate_Store certstores)
{
    if (end_certs.empty)
        throw new Invalid_Argument("x509_path_validate called with no subjects");
    
    Vector!X509_Certificate cert_path;
    cert_path.push_back(end_certs[0]);
    
    auto extra = scoped!Certificate_Store_Overlay(end_certs);
    
    // iterate until we reach a root or cannot find the issuer
    while (!cert_path.back().is_self_signed())
    {
        const X509_Certificate cert = find_issuing_cert(cert_path.back(), extra, certstores);
        if (!cert)
            return Path_Validation_Result(Certificate_Status_Code.CERT_ISSUER_NOT_FOUND);
        
        cert_path.push_back(*cert);
    }
    
    return Path_Validation_Result(check_chain(cert_path, restrictions, certstores),
                                  std.algorithm.move(cert_path));
}


/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(in X509_Certificate end_cert,
                                          in Path_Validation_Restrictions restrictions,
                                          in Vector!Certificate_Store certstores)
{
    Vector!X509_Certificate certs;
    certs.push_back(end_cert);
    return x509_path_validate(certs, restrictions, certstores);
}

/**
* PKIX Path Validation
*/

Path_Validation_Result x509_path_validate(in X509_Certificate end_cert,
                                          in Path_Validation_Restrictions restrictions,
                                          in Certificate_Store store)
{
    Vector!X509_Certificate certs;
    certs.push_back(end_cert);
    
    Vector!Certificate_Store certstores;
    certstores.push_back(&store);
    
    return x509_path_validate(certs, restrictions, certstores);
}
/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(in Vector!X509_Certificate end_certs,
                                          in Path_Validation_Restrictions restrictions,
                                          in Certificate_Store store)
{
    Vector!Certificate_Store certstores;
    certstores.push_back(&store);
    
    return x509_path_validate(end_certs, restrictions, certstores);
}

const X509_Certificate find_issuing_cert(in X509_Certificate cert,
                                         ref Certificate_Store end_certs, 
                                         in Vector!Certificate_Store certstores)
{
    const X509_DN issuer_dn = cert.issuer_dn();
    const Vector!ubyte auth_key_id = cert.authority_key_id();
    
    if (const X509_Certificate cert = end_certs.find_cert(issuer_dn, auth_key_id))
        return cert;
    
    foreach (certstore; certstores)
    {
        if (const X509_Certificate cert = certstore.find_cert(issuer_dn, auth_key_id))
            return cert;
    }
    
    return null;
}

const X509_CRL find_crls_for(in X509_Certificate cert,
                              const ref Vector!Certificate_Store certstores)
{
    foreach (certstore; certstores)
    {
        if (const X509_CRL crl = certstore.find_crl_for(cert))
            return crl;
    }

    /// todo: use crl distribution point and download the CRL
    version(none) {
        /*
        const string crl_url = cert.crl_distribution_point();
        if (crl_url != "")
        {
        std::cout << "Downloading CRL " << crl_url << "";
            auto http = HTTP::GET_sync(crl_url);
            
        std::cout << http.status_message() << "";
            
            http.throw_unless_ok();
            // check the mime type
            
            auto crl = X509_CRL(http.body());
            
            return crl;
        }*/
    }
    
    return null;
}

Vector!( RedBlackTree!Certificate_Status_Code )
    check_chain(in Vector!X509_Certificate cert_path,
                in Path_Validation_Restrictions restrictions,
                in Vector!Certificate_Store certstores)
{
    const RedBlackTree!string trusted_hashes = restrictions.trusted_hashes();
    
    const bool self_signed_ee_cert = (cert_path.length == 1);
    
    X509_Time current_time = X509_Time(Clock.currTime());
    
    Vector!( Tid ) ocsp_responses;
    
    Vector!( RedBlackTree!Certificate_Status_Code ) cert_status = Vector!( Vector!Certificate_Status_Code )( cert_path.length );
    
    foreach (size_t i; 0 .. cert_path.length)
    {
        auto status = &cert_status[i];
        
        const bool at_self_signed_root = (i == cert_path.length - 1);
        
        const X509_Certificate subject = cert_path[i];
        
        const X509_Certificate issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];
        
        const Certificate_Store trusted = certstores[0]; // fixme
        
        if (i == 0 || restrictions.ocsp_all_intermediates()) {
            version(Have_vibe_d)
                ocsp_responses.push_back(runTask(&online_check, issuer, subject, trusted));
            else
                ocsp_responses.push_back(spawn(&online_check, issuer, subject, trusted));

        }
        // Check all certs for valid time range
        if (current_time < X509_Time(subject.start_time()))
            status.insert(Certificate_Status_Code.CERT_NOT_YET_VALID);
        
        if (current_time > X509_Time(subject.end_time()))
            status.insert(Certificate_Status_Code.CERT_HAS_EXPIRED);
        
        // Check issuer constraints
        
        // Don't require CA bit set on self-signed end entity cert
        if (!issuer.is_CA_cert() && !self_signed_ee_cert)
            status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CERT_ISSUER);
        
        if (issuer.path_limit() < i)
            status.insert(Certificate_Status_Code.CERT_CHAIN_TOO_LONG);
        
        Unique!Public_Key issuer_key = issuer.subject_public_key();
        
        if (subject.check_signature(*issuer_key) == false)
            status.insert(Certificate_Status_Code.SIGNATURE_ERROR);
        
        if (issuer_key.estimated_strength() < restrictions.minimum_key_strength())
            status.insert(Certificate_Status_Code.SIGNATURE_METHOD_TOO_WEAK);
        
        // Allow untrusted hashes on self-signed roots
        if (!trusted_hashes.empty && !at_self_signed_root)
        {
            if (subject.hash_used_for_signature() !in trusted_hashes)
                status.insert(Certificate_Status_Code.UNTRUSTED_HASH);
        }
    }
    
    foreach (size_t i; 0 .. cert_path.length - 1)
    {

        auto status = &cert_status[i];
        
        const X509_Certificate subject = cert_path[i];
        const X509_Certificate ca = cert_path[i+1];
        
        if (i < ocsp_responses.length)
        {
            try
            {
                OCSP_Response ocsp = ocsp_responses[i].receiveOnly!(OCSP_Response)();
                
                auto ocsp_status = ocsp.status_for(ca, subject);
                
                status.insert(ocsp_status);
                
                //std::cout << "OCSP status: " << status_string(ocsp_status) << "\n";
                
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
        
        const X509_CRL crl_p = find_crls_for(subject, certstores);
        
        if (!crl_p)
        {
            if (restrictions.require_revocation_information())
                status.insert(Certificate_Status_Code.NO_REVOCATION_DATA);
            continue;
        }
        
        const X509_CRL crl = *crl_p;
        
        if (!ca.allowed_usage(CRL_SIGN))
            status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CRL_ISSUER);
        
        if (current_time < X509_Time(crl.this_update()))
            status.insert(Certificate_Status_Code.CRL_NOT_YET_VALID);
        
        if (current_time > X509_Time(crl.next_update()))
            status.insert(Certificate_Status_Code.CRL_HAS_EXPIRED);
        
        if (crl.check_signature(ca.subject_public_key()) == false)
            status.insert(Certificate_Status_Code.CRL_BAD_SIGNATURE);
        
        if (crl.is_revoked(subject))
            status.insert(Certificate_Status_Code.CERT_IS_REVOKED);
    }
    
    if (self_signed_ee_cert)
        cert_status.back().insert(Certificate_Status_Code.CANNOT_ESTABLISH_TRUST);
    
    return cert_status;
}