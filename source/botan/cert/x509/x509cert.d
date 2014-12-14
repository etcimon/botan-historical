/*
* X.509 Certificates
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509cert;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

public import botan.utils.datastor.datastor;
public import botan.pubkey.x509_key;
public import botan.cert.x509.x509_obj;
public import botan.asn1.x509_dn;
import botan.asn1.asn1_alt_name;
import botan.cert.x509.key_constraint;
import botan.cert.x509.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.containers.multimap;
import botan.utils.parsing;
import botan.math.bigint.bigint;
import botan.libstate.lookup;
import botan.asn1.oids;
import botan.codec.pem;
import botan.codec.hex;
import botan.utils.types;
import botan.utils.memory.memory;
import std.algorithm;
import std.array : Appender;

import botan.utils.containers.hashmap;

alias X509Certificate = FreeListRef!X509CertificateImpl;

/**
* This class represents X.509 Certificate
*/
final class X509CertificateImpl : X509Object
{
public:
    /**
    * Get the public key associated with this certificate.
    * @return subject public key of this certificate
    */
    PublicKey subjectPublicKey() const
    {
        return x509_key.loadKey(
            putInSequence(subjectPublicKeyBits()));
    }

    /**
    * Get the public key associated with this certificate.
    * @return subject public key of this certificate
    */
    Vector!ubyte subjectPublicKeyBits() const
    {
        return hexDecode(m_subject.get1("X509.Certificate.public_key"));
    }

    /**
    * Get the issuer certificate DN.
    * @return issuer DN of this certificate
    */
    X509DN issuerDn() const
    {
        return createDn(m_issuer);
    }

    /**
    * Get the subject certificate DN.
    * @return subject DN of this certificate
    */
    X509DN subjectDn() const
    {
        return createDn(m_subject);
    }

    /**
    * Get a value for a specific subject_info parameter name.
    * @param name = the name of the paramter to look up. Possible names are
    * "X509.Certificate.version", "X509.Certificate.serial",
    * "X509.Certificate.start", "X509.Certificate.end",
    * "X509.Certificate.v2.key_id", "X509.Certificate.public_key",
    * "X509v3.BasicConstraints.path_constraint",
    * "X509v3.BasicConstraints.is_ca", "X509v3.ExtendedKeyUsage",
    * "X509v3.CertificatePolicies", "X509v3.SubjectKeyIdentifier" or
    * "X509.Certificate.serial".
    * @return value(s) of the specified parameter
    */
    Vector!string
        subjectInfo(in string what) const
    {
        return m_subject.get(X509DN.derefInfoField(what));
    }

    /**
    * Get a value for a specific subject_info parameter name.
    * @param name = the name of the paramter to look up. Possible names are
    * "X509.Certificate.v2.key_id" or "X509v3.AuthorityKeyIdentifier".
    * @return value(s) of the specified parameter
    */
    Vector!string issuerInfo(in string what) const
    {
        return m_issuer.get(X509DN.derefInfoField(what));
    }

    /**
    * Raw subject DN
    */
    Vector!ubyte rawIssuerDn() const
    {
        return m_issuer.get1Memvec("X509.Certificate.dn_bits");
    }


    /**
    * Raw issuer DN
    */
    Vector!ubyte rawSubjectDn() const
    {
        return m_subject.get1Memvec("X509.Certificate.dn_bits");
    }

    /**
    * Get the notBefore of the certificate.
    * @return notBefore of the certificate
    */
    string startTime() const
    {
        return m_subject.get1("X509.Certificate.start");
    }

    /**
    * Get the notAfter of the certificate.
    * @return notAfter of the certificate
    */
    string endTime() const
    {
        return m_subject.get1("X509.Certificate.end");
    }

    /**
    * Get the X509 version of this certificate object.
    * @return X509 version
    */
    uint x509Version() const
    {
        return (m_subject.get1Uint("X509.Certificate.version") + 1);
    }

    /**
    * Get the serial number of this certificate.
    * @return certificates serial number
    */
    Vector!ubyte serialNumber() const
    {
        return m_subject.get1Memvec("X509.Certificate.serial");
    }

    /**
    * Get the DER encoded AuthorityKeyIdentifier of this certificate.
    * @return DER encoded AuthorityKeyIdentifier
    */
    Vector!ubyte authorityKeyId() const
    {
        return m_issuer.get1Memvec("X509v3.AuthorityKeyIdentifier");
    }

    /**
    * Get the DER encoded SubjectKeyIdentifier of this certificate.
    * @return DER encoded SubjectKeyIdentifier
    */
    Vector!ubyte subjectKeyId() const
    {
        return m_subject.get1Memvec("X509v3.SubjectKeyIdentifier");
    }

    /**
    * Check whether this certificate is self signed.
    * @return true if this certificate is self signed
    */
    bool isSelfSigned() const { return m_self_signed; }

    /**
    * Check whether this certificate is a CA certificate.
    * @return true if this certificate is a CA certificate
    */
    bool isCACert() const
    {
        if (!m_subject.get1Uint("X509v3.BasicConstraints.is_ca"))
            return false;
        
        return allowedUsage(KEY_CERT_SIGN);
    }


    bool allowedUsage(KeyConstraints usage) const
    {
        if (constraints() == KeyConstraints.NO_CONSTRAINTS)
            return true;
        return (constraints() & usage);
    }

    /**
    * Returns true if and only if name (referring to an extended key
    * constraint, eg "PKIX.ServerAuth") is included in the extended
    * key extension.
    */
    bool allowedUsage(in string usage) const
    {
        foreach (constraint; exConstraints())
            if (constraint == usage)
                return true;
        
        return false;
    }

    /**
    * Get the path limit as defined in the BasicConstraints extension of
    * this certificate.
    * @return path limit
    */
    uint pathLimit() const
    {
        return m_subject.get1Uint("X509v3.BasicConstraints.path_constraint", 0);
    }

    /**
    * Get the key constraints as defined in the KeyUsage extension of this
    * certificate.
    * @return key constraints
    */
    KeyConstraints constraints() const
    {
        return KeyConstraints(m_subject.get1Uint("X509v3.KeyUsage",
                                                 KeyConstraints.NO_CONSTRAINTS));
    }

    /**
    * Get the key constraints as defined in the ExtendedKeyUsage
    * extension of this
    * certificate.
    * @return key constraints
    */
    Vector!string exConstraints() const
    {
        return lookupOids(m_subject.get("X509v3.ExtendedKeyUsage"));
    }

    /**
    * Get the policies as defined in the CertificatePolicies extension
    * of this certificate.
    * @return certificate policies
    */
    Vector!string policies() const
    {
        return lookupOids(m_subject.get("X509v3.CertificatePolicies"));
    }

    /**
    * Return the listed address of an OCSP responder, or empty if not set
    */
    string ocspResponder() const
    {
        return m_subject.get1("OCSP.responder", "");
    }

    /**
    * Return the CRL distribution point, or empty if not set
    */
    string crlDistributionPoint() const
    {
        return m_subject.get1("CRL.DistributionPoint", "");
    }

    /**
    * @return a string describing the certificate
    */

    override string toString() const
    {
        import std.array : Appender;
        __gshared immutable string[] dn_fields = [ "Name",
            "Email",
            "Organization",
            "Organizational Unit",
            "Locality",
            "State",
            "Country",
            "IP",
            "DNS",
            "URI",
            "PKIX.XMPPAddr" ];
        
        Appender!string output;
        
        foreach (const dn_field; dn_fields)
        {
            const Vector!string vals = subjectInfo(dn_field);
            
            if (vals.empty)
                continue;
            
            output ~= "Subject " ~ dn_field ~ ":";
            for (size_t j = 0; j != vals.length; ++j)
                output ~= " " ~ vals[j];
            output ~= "";
        }
        
        foreach (const dn_field; dn_fields)
        {
            const Vector!string vals = issuerInfo(dn_field);
            
            if (vals.empty)
                continue;
            
            output ~= "Issuer " ~ dn_field ~ ":";
            for (size_t j = 0; j != vals.length; ++j)
                output ~= " " ~ vals[j];
            output ~= "";
        }
        
        output ~= "Version: " ~ x509Version();
        
        output ~= "Not valid before: " ~ startTime();
        output ~= "Not valid after: " ~ endTime();
        
        output ~= "Constraints:";
        KeyConstraints constraints = constraints();
        if (constraints == KeyConstraints.NO_CONSTRAINTS)
            output ~= " None";
        else
        {
            if (constraints & DIGITAL_SIGNATURE)
                output ~= "    Digital Signature";
            if (constraints & NON_REPUDIATION)
                output ~= "    Non-Repuidation";
            if (constraints & KEY_ENCIPHERMENT)
                output ~= "    Key Encipherment";
            if (constraints & DATA_ENCIPHERMENT)
                output ~= "    Data Encipherment";
            if (constraints & KEY_AGREEMENT)
                output ~= "    Key Agreement";
            if (constraints & KEY_CERT_SIGN)
                output ~= "    Cert Sign";
            if (constraints & CRL_SIGN)
                output ~= "    CRL Sign";
        }
        
        Vector!string policies = policies();
        if (!policies.empty)
        {
            output ~= "Policies: ";
            foreach (const policy; policies[])
                output ~= "    " ~ policy;
        }
        
        Vector!string ex_constraints = exConstraints();
        if (!ex_constraints.empty)
        {
            output ~= "Extended Constraints:";
            foreach (const ex_constraint; ex_constraints[])
                output ~= "    " ~ ex_constraint;
        }
        
        if (ocspResponder() != "")
            output ~= "OCSP responder " ~ ocspResponder();
        if (crlDistributionPoint() != "")
            output ~= "CRL " ~ crlDistributionPoint();
        
        output ~= "Signature algorithm: " ~ OIDS.lookup(signatureAlgorithm().oid);
        
        output ~= "Serial number: " ~ hexEncode(serialNumber());
        
        if (authorityKeyId().length)
            output ~= "Authority keyid: " ~ hexEncode(authorityKeyId());
        
        if (subjectKeyId().length)
            output ~= "Subject keyid: " ~ hexEncode(subjectKeyId());
        
        Unique!X509PublicKey pubkey = subjectPublicKey();
        output ~= "Public Key:" ~ x509_key.PEM_encode(*pubkey);
        
        return output.data;
    }


    /**
    * Return a fingerprint of the certificate
    */
    string fingerprint(in string hash_name) const
    {
        Unique!HashFunction hash = getHash(hash_name);
        hash.update(BER_encode());
        const auto hex_print = hexEncode(hash.finished());
        
        string formatted_print;
        
        for (size_t i = 0; i != hex_print.length; i += 2)
        {
            formatted_print.pushBack(hex_print[i]);
            formatted_print.pushBack(hex_print[i+1]);
            
            if (i != hex_print.length - 2)
                formatted_print.pushBack(':');
        }
        
        return formatted_print;
    }

    /**
    * Check if a certain DNS name matches up with the information in
    * the cert
    */
    bool matchesDnsName(in string name) const
    {
        if (name == "")
            return false;
        
        if (certSubjectDnsMatch(name, subjectInfo("DNS")))
            return true;
        
        if (certSubjectDnsMatch(name, subjectInfo("Name")))
            return true;
        
        return false;
    }

    /**
    * Check to certificates for equality.
    * @return true both certificates are (binary) equal
    */
    bool opEquals(in X509Certificate other) const
    {
        return (sig == other.sig &&
                sig_algo == other.sig_algo &&
                m_self_signed == other.m_self_signed &&
                m_issuer == other.m_issuer &&
                m_subject == other.m_subject);
    }

    /**
    * Impose an arbitrary (but consistent) ordering
    * @return true if this is less than other by some unspecified criteria
    */
    bool opBinary(string op)(in X509Certificate other) const
        if (op == "<")
    {
        /* If signature values are not equal, sort by lexicographic ordering of that */
        if (sig != other.sig)
        {
            if (sig < other.sig)
                return true;
            return false;
        }
        
        // Then compare the signed contents
        return tbs_bits < other.tbs_bits;
    }

    /**
    * Check two certificates for ineah jsais sadfadfasfaquality
    * @return true if the arguments represent different certificates,
    * false if they are binary identical
    */
    bool opCmp(in X509Certificate cert2)
    {
        if (cert1 == cert2) return 0;
        else return -1;
    }


    /**
    * Create a certificate from a data source providing the DER or
    * PEM encoded certificate.
    * @param source = the data source
    */
    this(DataSource input)
    {
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    /**
    * Create a certificate from a file containing the DER or PEM
    * encoded certificate.
    * @param filename = the name of the certificate file
    */
    this(in string filename)
    {
        super(filename, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    this(in Vector!ubyte input)
    {
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

private:
    /*
    * Decode the TBSCertificate data
    */
    void forceDecode()
    {
        size_t _version;
        BigInt serial_bn;
        AlgorithmIdentifier sig_algo_inner;
        X509DN dn_issuer, dn_subject;
        X509Time start, end;
        
        BERDecoder tbsCert(tbs_bits);
        
        tbs_cert.decodeOptional(_version, (cast(ASN1Tag) 0),
                                 (ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
            .decode(serial_bn)
                .decode(sig_algo_inner)
                .decode(dn_issuer)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(start)
                .decode(end)
                .verifyEnd()
                .endCons()
                .decode(dn_subject);
        
        if (_version > 2)
            throw new DecodingError("Unknown X.509 cert version " ~ to!string(_version));
        if (sig_algo != sig_algo_inner)
            throw new DecodingError("Algorithm identifier mismatch");
        
        m_self_signed = (dn_subject == dn_issuer);
        
        m_subject.add(dn_subject.contents());
        m_issuer.add(dn_issuer.contents());
        
        m_subject.add("X509.Certificate.dn_bits", putInSequence(dn_subject.getBits()));
        m_issuer.add("X509.Certificate.dn_bits", putInSequence(dn_issuer.getBits()));
        
        BERObject public_key = tbs_cert.getNextObject();
        if (public_key.type_tag != ASN1Tag.SEQUENCE || public_key.class_tag != ASN1Tag.CONSTRUCTED)
            throw new BERBadTag("X509Certificate: Unexpected tag for public key",
                                  public_key.type_tag, public_key.class_tag);
        
        Vector!ubyte v2_issuer_key_id, v2_subject_key_id;
        
        tbs_cert.decodeOptionalString(v2_issuer_key_id, ASN1Tag.BIT_STRING, 1);
        tbs_cert.decodeOptionalString(v2_subject_key_id, ASN1Tag.BIT_STRING, 2);
        
        BERObject v3_exts_data = tbs_cert.getNextObject();
        if (v3_exts_data.type_tag == 3 &&
            v3_exts_data.class_tag == (ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
        {
            X509Extensions extensions;
            
            BERDecoder(v3_exts_data.value).decode(extensions).verifyEnd();
            
            extensions.contentsTo(m_subject, m_issuer);
        }
        else if (v3_exts_data.type_tag != ASN1Tag.NO_OBJECT)
            throw new BERBadTag("Unknown tag in X.509 cert",
                                  v3_exts_data.type_tag, v3_exts_data.class_tag);
        
        if (tbs_cert.moreItems())
            throw new DecodingError("TBSCertificate has more items that expected");
        
        m_subject.add("X509.Certificate.version", _version);
        m_subject.add("X509.Certificate.serial", BigInt.encode(serial_bn));
        m_subject.add("X509.Certificate.start", start.readableString());
        m_subject.add("X509.Certificate.end", end.readableString());
        
        m_issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
        m_subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);
        
        m_subject.add("X509.Certificate.public_key",
                    hexEncode(public_key.value));
        
        if (m_self_signed && _version == 0)
        {
            m_subject.add("X509v3.BasicConstraints.is_ca", 1);
            m_subject.add("X509v3.BasicConstraints.path_constraint", NO_CERT_PATH_LIMIT);
        }
        
        if (is_CA_cert() &&
            !m_subject.hasValue("X509v3.BasicConstraints.path_constraint"))
        {
            const size_t limit = (x509Version() < 3) ? NO_CERT_PATH_LIMIT : 0;
            
            m_subject.add("X509v3.BasicConstraints.path_constraint", limit);
        }
    }


    this() {}

    DataStore m_subject, m_issuer;
    bool m_self_signed;
}


/*
* Data Store Extraction Operations
*/
/*
* Create and populate a X509DN
*/
X509DN createDn(in DataStore info)
{
    auto names = info.searchFor((in string key, in string)
    {
        return (key.canFind("X520."));
    });
    
    X509DN dn;
    
    foreach (key, value; names)
        dn.addAttribute(key, value);
    
    return dn;
}


/*
* Create and populate an AlternativeName
*/
AlternativeName createAltName(in DataStore info)
{
    auto names = info.searchFor((in string key, in string)
                                 { return (key == "RFC822" || key == "DNS" || key == "URI" || key == "IP"); });
    
    AlternativeName alt_name;
    
    foreach (key, value; names)
        alt_name.addAttribute(key, value);
    
    return alt_name;
}



/*
* Lookup each OID in the vector
*/
Vector!string lookupOids(in Vector!string input)
{
    Vector!string output;
    
    foreach (oid_name; input)
        output.pushBack(OIDS.lookup(OID(oid_name)));
    return output;
}


bool certSubjectDnsMatch(in string name,
                            const Vector!string cert_names)
{
    foreach (const cn; cert_names)
    {
        if (cn == name)
            return true;
        
        /*
        * Possible wildcard match. We only support the most basic form of
        * cert wildcarding ala RFC 2595
        */
        if (cn.length > 2 && cn[0] == '*' && cn[1] == '.' && name.length > cn.length)
        {
            const string base = cn[1 .. $];
            size_t start = name.length - base.length;
            if (name[start .. start + base.length] == base)
                return true;
        }
    }
    
    return false;
}