/*
* X.509 Self-Signed Certificate
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509self;
import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES) :

alias x509self = botan.cert.x509.x509self;

public import botan.cert.x509.x509_ca;
public import botan.cert.x509.x509cert;
public import botan.asn1.asn1_time;
import botan.cert.x509.pkcs10;
import botan.cert.x509.x509_ext;
import botan.cert.x509.key_constraint;
import botan.asn1.oids;
import botan.asn1.der_enc;
import botan.asn1.asn1_attribute;
import botan.asn1.asn1_alt_name;
import botan.filters.pipe;
import botan.utils.types;
import botan.utils.parsing;
import botan.pubkey.pkcs8;
import std.array;
import std.datetime;

/**
* Options for X.509 certificates.
*/
struct X509CertOptions
{
public:
    /**
    * the subject common name
    */
    string common_name;

    /**
    * the subject counry
    */
    string country;

    /**
    * the subject organization
    */
    string organization;

    /**
    * the subject organizational unit
    */
    string org_unit;

    /**
    * the subject locality
    */
    string locality;

    /**
    * the subject state
    */
    string state;

    /**
    * the subject serial number
    */
    string serial_number;

    /**
    * the subject email adress
    */
    string email;

    /**
    * the subject URI
    */
    string uri;

    /**
    * the subject IPv4 address
    */
    string ip;

    /**
    * the subject DNS
    */
    string dns;

    /**
    * the subject XMPP
    */
    string xmpp;

    /**
    * the subject challenge password
    */
    string challenge;

    /**
    * the subject notBefore
    */
    X509Time start;
    /**
    * the subject notAfter
    */
    X509Time end;

    /**
    * Indicates whether the certificate request
    */
    bool is_CA;

    /**
    * Indicates the BasicConstraints path limit
    */
    size_t path_limit;

    /**
    * The key constraints for the subject public key
    */
    KeyConstraints constraints;

    /**
    * The key extended constraints for the subject public key
    */
    Array!OID ex_constraints;

    /**
    * Check the options set in this object for validity.
    */
    void sanityCheck() const
    {
        if (common_name == "" || country == "")
            throw new EncodingError("X.509 certificate: name and country MUST be set");
        if (country.length != 2)
            throw new EncodingError("Invalid ISO country code: " ~ country);
        if (start >= end)
            throw new EncodingError("X509_Cert_Options: invalid time constraints");
    }
    


    /**
    * Mark the certificate as a CA certificate and set the path limit.
    * @param limit = the path limit to be set in the BasicConstraints extension.
    */
    void cAKey(size_t limit = 1)
    {
        is_CA = true;
        path_limit = limit;
    }


    /**
    * Set when the certificate should become valid
    * @param time = the notBefore value of the certificate
    */
    void notBefore(in string time_string)
    {
        start = X509Time(time_string);
    }

    /**
    * Set the notAfter of the certificate.
    * @param time = the notAfter value of the certificate
    */
    void notAfter(in string time_string)
    {
        end = X509Time(time_string);
    }

    /**
    * Add the key constraints of the KeyUsage extension.
    * @param constr = the constraints to set
    */
    void addConstraints(KeyConstraints usage)
    {
        constraints = usage;
    }

    /**
    * Add constraints to the ExtendedKeyUsage extension.
    * @param oid = the oid to add
    */
    void addExConstraint(OID oid)
    {
        ex_constraints.pushBack(oid);
    }

    /**
    * Add constraints to the ExtendedKeyUsage extension.
    * @param name = the name to look up the oid to add
    */
    void addExConstraint(in string oid_str)
    {
        ex_constraints.pushBack(OIDS.lookup(oid_str));
    }

    /**
    * Construct a new options object
    * @param opts = define the common name of this object. An example for this
    * parameter would be "common_name/country/organization/organizational_unit".
    * @param expire_time = the expiration time (default 1 year)
    */
    this(in string initial_opts = "", Duration expiration_time = 365.days)
    {
        is_CA = false;
        path_limit = 0;
        constraints = KeyConstraints.NO_CONSTRAINTS;
        
        auto now = Clock.currTime();
        
        start = X509Time(now);
        end = X509Time(now + expiration_time);
        
        if (initial_opts == "")
            return;
        
        Vector!string parsed = initial_opts.split('/');
        
        if (parsed.length > 4)
            throw new InvalidArgument("X.509 cert options: Too many names: " ~ initial_opts);
        
        if (parsed.length >= 1) common_name      = parsed[0];
        if (parsed.length >= 2) country            = parsed[1];
        if (parsed.length >= 3) organization     = parsed[2];
        if (parsed.length == 4) org_unit          = parsed[3];
    }
}

/**
* Create a self-signed X.509 certificate.
* @param opts = the options defining the certificate to create
* @param key = the private key used for signing, i.e. the key
* associated with this self-signed certificate
* @param hash_fn = the hash function to use
* @param rng = the rng to use
* @return newly created self-signed certificate
*/
X509Certificate createSelfSignedCert(in X509CertOptions opts,
                                     in PrivateKey key,
                                     in string hash_fn,
                                     RandomNumberGenerator rng)
{
    AlgorithmIdentifier sig_algo;
    X509DN subject_dn;
    AlternativeName subject_alt;
    
    opts.sanityCheck();
    
    Vector!ubyte pub_key = x509_key.BER_encode(key);
    PKSigner signer = chooseSigFormat(key, hash_fn, sig_algo);
    loadInfo(opts, subject_dn, subject_alt);
    
    KeyConstraints constraints;
    if (opts.is_CA)
        constraints = KeyConstraints.KEY_CERT_SIGN | KeyConstraints.CRL_SIGN;
    else
        constraints = findConstraints(key, opts.constraints);
    
    X509Extensions extensions;
    
    extensions.add(new BasicConstraints(opts.is_CA, opts.path_limit), true);
    
    extensions.add(new KeyUsage(constraints), true);
    
    extensions.add(new SubjectKeyID(pub_key));
    
    extensions.add(new SubjectAlternativeName(subject_alt));
    
    extensions.add(new ExtendedKeyUsage(*cast(Vector!OID*) &opts.ex_constraints));
    
    return X509CA.makeCert(signer, rng, sig_algo, pub_key,
                           opts.start, opts.end,
                           subject_dn, subject_dn,
                           extensions);
}

/**
* Create a PKCS#10 certificate request.
* @param opts = the options defining the request to create
* @param key = the key used to sign this request
* @param rng = the rng to use
* @param hash_fn = the hash function to use
* @return newly created PKCS#10 request
*/
PKCS10Request createCertReq(in X509CertOptions opts,
                               in PrivateKey key,
                               in string hash_fn,
                               RandomNumberGenerator rng)
{
    AlgorithmIdentifier sig_algo;
    X509DN subject_dn;
    AlternativeName subject_alt;
    
    opts.sanityCheck();
    
    Vector!ubyte pub_key = x509_key.BER_encode(key);
    PKSigner signer = chooseSigFormat(key, hash_fn, sig_algo);
    loadInfo(opts, subject_dn, subject_alt);
    
    __gshared immutable size_t PKCS10_VERSION = 0;
    
    X509Extensions extensions;
    
    extensions.add(new BasicConstraints(opts.is_CA, opts.path_limit));
    extensions.add(new KeyUsage(opts.is_CA ? KeyConstraints.KEY_CERT_SIGN | KeyConstraints.CRL_SIGN : findConstraints(key, opts.constraints)));
    extensions.add(new ExtendedKeyUsage(*cast(Vector!OID*)&opts.ex_constraints));
    extensions.add(new SubjectAlternativeName(subject_alt));
    
    DEREncoder tbs_req;
    
    tbs_req.startCons(ASN1Tag.SEQUENCE)
            .encode(PKCS10_VERSION)
            .encode(subject_dn)
            .rawBytes(pub_key)
            .startExplicit(0);
    
    if (opts.challenge != "")
    {
        ASN1String challenge = ASN1String(opts.challenge, ASN1Tag.DIRECTORY_STRING);
        
        tbs_req.encode(Attribute("PKCS9.ChallengePassword", DEREncoder().encode(challenge).getContentsUnlocked()));
    }
    
    tbs_req.encode(Attribute("PKCS9.ExtensionRequest",
                      DEREncoder()
                      .startCons(ASN1Tag.SEQUENCE)
                      .encode(extensions)
                      .endCons()
                      .getContentsUnlocked()
                      )
                   ).endExplicit().endCons();
            
    const Vector!ubyte req = X509Object.makeSigned(signer, rng, sig_algo, tbs_req.getContents());
    
    return PKCS10Request(req);
}

/*
* Load information from the X509_Cert_Options
*/
private void loadInfo(in X509CertOptions opts, 
                      X509DN subject_dn,
                      AlternativeName subject_alt)
{
    subject_dn.addAttribute("X520.CommonName", opts.common_name);
    subject_dn.addAttribute("X520.Country", opts.country);
    subject_dn.addAttribute("X520.State", opts.state);
    subject_dn.addAttribute("X520.Locality", opts.locality);
    subject_dn.addAttribute("X520.Organization", opts.organization);
    subject_dn.addAttribute("X520.OrganizationalUnit", opts.org_unit);
    subject_dn.addAttribute("X520.SerialNumber", opts.serial_number);
    subject_alt = AlternativeName(opts.email, opts.uri, opts.dns, opts.ip);
    subject_alt.addOthername(OIDS.lookup("PKIX.XMPPAddr"), opts.xmpp, ASN1Tag.UTF8_STRING);
}