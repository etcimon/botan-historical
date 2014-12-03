/*
* X.509 Certificate Extensions
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_ext;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.utils.datastor.datastor;
import botan.cert.x509.crl_ent;
import botan.cert.x509.key_constraint;
import botan.hash.sha160;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import botan.utils.charset;
import botan.utils.bit_ops;
import std.algorithm;
import botan.utils.types;
import botan.utils.containers.multimap;

/**
* X.509 Certificate Extension
*/
class CertificateExtension
{
public:
    /**
    * @return OID representing this extension
    */
    final OID oidOf() const
    {
        return OIDS.lookup(oid_name());
    }

    /**
    * Make a copy of this extension
    * @return copy of this
    */
    abstract CertificateExtension copy() const;

    /*
    * Add the contents of this extension into the information
    * for the subject and/or issuer, as necessary.
    * @param subject = the subject info
    * @param issuer = the issuer info
    */
    abstract void contentsTo(ref DataStore subject,
                              ref DataStore issuer) const;

    /*
    * @return specific OID name
    */
    abstract string oidName() const;

    ~this() {}
protected:
    abstract bool shouldEncode() const { return true; }
    abstract Vector!ubyte encodeInner() const;
    abstract void decodeInner(in Vector!ubyte);
}

alias X509Extensions = FreeListRef!X509ExtensionsImpl;

/**
* X.509 Certificate Extension List
*/
final class X509ExtensionsImpl : ASN1Object
{
public:

    void encodeInto(DEREncoder to) const
    {
        foreach (const extension; m_extensions)
        {
            const Certificate_Extension ext = extension.first;
            const bool is_critical = extension.second;
            
            const bool should_encode = ext.should_encode();
            
            if (should_encode)
            {
                to_object.startCons(ASN1Tag.SEQUENCE)
                           .encode(ext.oidOf())
                        .encodeOptional(is_critical, false)
                        .encode(ext.encodeInner(), ASN1Tag.OCTET_STRING)
                        .endCons();
            }
        }
    }

    void decodeFrom(BERDecoder from_source)
    {
        foreach (extension; m_extensions)
            delete extension.first;
        m_extensions.clear();
        
        BERDecoder sequence = from_source.startCons(ASN1Tag.SEQUENCE);
        
        while (sequence.moreItems())
        {
            OID oid;
            Vector!ubyte value;
            bool critical;
            
            sequence.startCons(ASN1Tag.SEQUENCE)
                    .decode(oid)
                    .decodeOptional(critical, BOOLEAN, ASN1Tag.UNIVERSAL, false)
                    .decode(value, ASN1Tag.OCTET_STRING)
                    .verifyEnd()
                    .endCons();
            
            Certificate_Extension ext = get_extension(oid);
            
            if (!ext && critical && m_throw_on_unknown_critical)
                throw new DecodingError("Encountered unknown X.509 extension marked "
                                         ~ "as critical; OID = " ~ oid.toString());
            
            if (ext)
            {
                try
                {
                    ext.decodeInner(value);
                }
                catch(Exception e)
                {
                    throw new DecodingError("Exception while decoding extension " ~
                                             oid.toString() ~ ": " ~ e.msg);
                }
                
                m_extensions.pushBack(Pair(ext, critical));
            }
        }
        
        sequence.verifyEnd();
    }

    void contentsTo(ref DataStore subject_info,
                     ref DataStore issuer_info) const
    {
        foreach (extension; m_extensions)
            extension.first.contentsTo(subject_info, issuer_info);
    }

    void add(CertificateExtension extn, bool critical)
    {
        m_extensions.pushBack(Pair(extn, critical));
    }

    X509Extensions opAssign(in X509Extensions other)
    {
        foreach (extension; m_extensions)
            delete extension.first;
        m_extensions.clear();
        
        foreach (extension; other.m_extensions)
            m_extensions.pushBack(Pair(extension.first.copy(), extension.second));
        
        return this;
    }

    this(in X509Extensions ext) {
        this = ext;
    }

    this(bool st = true) { m_throw_on_unknown_critical = st; }

    ~this()
    {
        foreach (extension; m_extensions)
            delete extension.first;
    }

private:

    /*
    * List of X.509 Certificate Extensions
    */
    CertificateExtension getExtension(in OID oid)
    {
        string x509EXTENSION(string NAME, alias T)() {
            return `if (OIDS.name_of(oid, "` ~ NAME ~ `")) return new ` ~ __traits(T, identifier).stringof ~ `();`;
        }
        
        mixin( X509_EXTENSION!("X509v3.KeyUsage", KeyUsage)() );
        mixin( X509_EXTENSION!("X509v3.BasicConstraints", BasicConstraints)() );
        mixin( X509_EXTENSION!("X509v3.SubjectKeyIdentifier", SubjectKeyID)() );
        mixin( X509_EXTENSION!("X509v3.AuthorityKeyIdentifier", AuthorityKeyID)() );
        mixin( X509_EXTENSION!("X509v3.ExtendedKeyUsage", ExtendedKeyUsage)() );
        mixin( X509_EXTENSION!("X509v3.IssuerAlternativeName", IssuerAlternativeName)() );
        mixin( X509_EXTENSION!("X509v3.SubjectAlternativeName", SubjectAlternativeName)() );
        mixin( X509_EXTENSION!("X509v3.CertificatePolicies", CertificatePolicies)() );
        mixin( X509_EXTENSION!("X509v3.CRLDistributionPoints", CRLDistributionPoints)() );
        mixin( X509_EXTENSION!("PKIX.AuthorityInformationAccess", AuthorityInformationAccess)() );
        mixin( X509_EXTENSION!("X509v3.CRLNumber", CRLNumber)() );
        mixin( X509_EXTENSION!("X509v3.ReasonCode", CRLReasonCode)() );
        
        return null;
    }


    Vector!( Pair!(Certificate_Extension, bool)  ) m_extensions;
    bool m_throw_on_unknown_critical;
}

__gshared immutable size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
final class BasicConstraints : Certificate_Extension
{
public:
    BasicConstraints copy() const
    { return new BasicConstraints(m_is_ca, path_limit); }

    this(bool ca = false, size_t limit = 0)
    {
        m_is_ca = ca;
        m_path_limit = limit; 
    }

    bool getIsCa() const { return m_is_ca; }
    /*
    * Checked accessor for the path_limit member
    */
    size_t getPathLimit() const
    {
        if (!m_is_ca)
            throw new InvalidState("Basic_Constraints::get_path_limit: Not a CA");
        return m_path_limit;
    }

private:
    string oidName() const { return "X509v3.BasicConstraints"; }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encodeIf (m_is_ca,
                            DEREncoder()
                                .encode(m_is_ca)
                                .encodeOptional(m_path_limit, NO_CERT_PATH_LIMIT)
                            )
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeOptional(m_is_ca, BOOLEAN, ASN1Tag.UNIVERSAL, false)
                .decodeOptional(m_path_limit, INTEGER, ASN1Tag.UNIVERSAL, NO_CERT_PATH_LIMIT)
                .verifyEnd()
                .endCons();
        
        if (m_is_ca == false)
            m_path_limit = 0;
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.BasicConstraints.is_ca", (m_is_ca ? 1 : 0));
        subject.add("X509v3.BasicConstraints.path_constraint", m_path_limit);
    }

    bool m_is_ca;
    size_t m_path_limit;
}

/**
* Key Usage Constraints Extension
*/
final class KeyUsage : Certificate_Extension
{
public:
    KeyUsage copy() const { return new KeyUsage(m_constraints); }

    this(KeyConstraints c = KeyConstraints.NO_CONSTRAINTS) { constraints = c; }

    KeyConstraints getConstraints() const { return constraints; }
private:
    string oidName() const { return "X509v3.KeyUsage"; }

    bool shouldEncode() const { return (constraints != KeyConstraints.NO_CONSTRAINTS); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        if (m_constraints == KeyConstraints.NO_CONSTRAINTS)
            throw new EncodingError("Cannot encode zero usage constraints");
        
        const size_t unused_bits = low_bit(m_constraints) - 1;
        
        Vector!ubyte der;
        der.pushBack(ASN1Tag.BIT_STRING);
        der.pushBack(2 + ((unused_bits < 8) ? 1 : 0));
        der.pushBack(unused_bits % 8);
        der.pushBack((m_constraints >> 8) & 0xFF);
        if (m_constraints & 0xFF)
            der.pushBack(m_constraints & 0xFF);
        
        return der;
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder ber = BERDecoder(input);
        
        BER_Object obj = ber.getNextObject();
        
        if (obj.type_tag != ASN1Tag.BIT_STRING || obj.class_tag != ASN1Tag.UNIVERSAL)
            throw new BERBadTag("Bad tag for usage constraint",
                                  obj.type_tag, obj.class_tag);
        
        if (obj.value.length != 2 && obj.value.length != 3)
            throw new BERDecodingError("Bad size for BITSTRING in usage constraint");
        
        if (obj.value[0] >= 8)
            throw new BERDecodingError("Invalid unused bits in usage constraint");
        
        obj.value[obj.value.length-1] &= (0xFF << obj.value[0]);
        
        ushort usage = 0;
        foreach (size_t i; 1 .. obj.value.length)
            usage = (obj.value[i] << 8) | usage;
        
        m_constraints = KeyConstraints(usage);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.KeyUsage", m_constraints);
    }

    KeyConstraints m_constraints;
}

/**
* Subject Key Identifier Extension
*/
final class SubjectKeyID : Certificate_Extension
{
public:
    SubjectKeyID copy() const { return new SubjectKeyID(m_key_id); }

    this() {}
    this(in Vector!ubyte pub_key)
    {
        SHA_160 hash;
        m_key_id = unlock(hash.process(pub_key));
    }


    Vector!ubyte getKeyId() const { return m_key_id; }
private:
    string oidName() const { return "X509v3.SubjectKeyIdentifier"; }

    bool shouldEncode() const { return (m_key_id.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_key_id, ASN1Tag.OCTET_STRING).getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input).decode(m_key_id, ASN1Tag.OCTET_STRING).verifyEnd();
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.SubjectKeyIdentifier", m_key_id);
    }

    Vector!ubyte m_key_id;
}

/**
* Authority Key Identifier Extension
*/
class AuthorityKeyID : Certificate_Extension
{
public:
    AuthorityKeyID copy() const { return new AuthorityKeyID(m_key_id); }

    this() {}
    this(in Vector!ubyte k) { m_key_id = k; }

    Vector!ubyte getKeyId() const { return m_key_id; }
private:
    string oidName() const { return "X509v3.AuthorityKeyIdentifier"; }

    bool shouldEncode() const { return (m_key_id.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
                .encode(m_key_id, ASN1Tag.OCTET_STRING, ASN1Tag(0), ASN1Tag.CONTEXT_SPECIFIC)
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input)
            .startCons(ASN1Tag.SEQUENCE)
                .decodeOptionalString(m_key_id, ASN1Tag.OCTET_STRING, 0);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore, ref DataStore issuer) const
    {
        if (m_key_id.length)
            issuer.add("X509v3.AuthorityKeyIdentifier", m_key_id);
    }


    Vector!ubyte m_key_id;
}

/**
* Alternative Name Extension Base Class
*/
class AlternativeName : Certificate_Extension
{
public:
    AlternativeName getAltName() const { return m_alt_name; }

protected:

    this(in AlternativeName alt_name,
         in string oid_name_str)
    {
        m_alt_name = alt_name;
        m_oid_name_str = oid_name_str;
    }

private:
    string oidName() const { return m_oid_name_str; }

    bool shouldEncode() const { return m_alt_name.hasItems(); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_alt_name).getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input).decode(m_alt_name);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject_info,
                     ref DataStore issuer_info) const
    {
        MultiMap!(string, string) contents = get_alt_name().contents();
        
        if (m_oid_name_str == "X509v3.SubjectAlternativeName")
            subject_info.add(contents);
        else if (m_oid_name_str == "X509v3.IssuerAlternativeName")
            issuer_info.add(contents);
        else
            throw new InternalError("In AlternativeName, unknown type " ~
                                     m_oid_name_str);
    }

    string m_oid_name_str;
    AlternativeName m_alt_name;
}




/**
* Subject Alternative Name Extension
*/
final class SubjectAlternativeName : AlternativeName
{
public:
    SubjectAlternativeName copy() const
    { return new SubjectAlternativeName(get_alt_name()); }

    this() {}
    this(in AlternativeName name = new SubjectAlternativeName()) {
        super(name, "X509v3.SubjectAlternativeName");
    }
}

/**
* Issuer Alternative Name Extension
*/
final class IssuerAlternativeName : AlternativeName
{
public:
    IssuerAlternativeName copy() const
    { return new IssuerAlternativeName(get_alt_name()); }

    this(in AlternativeName name = new IssuerAlternativeName()) {
        super(name, "X509v3.IssuerAlternativeName");
    }
}

/**
* Extended Key Usage Extension
*/
final class ExtendedKeyUsage : Certificate_Extension
{
public:
    ExtendedKeyUsage copy() const { return new ExtendedKeyUsage(m_oids); }

    this() {}
    this(in Vector!OID o) 
    {
        m_oids = o;
    }

    Vector!OID getOids() const { return m_oids; }
private:
    string oidName() const { return "X509v3.ExtendedKeyUsage"; }

    bool shouldEncode() const { return (m_oids.length > 0); }
    /*
* Encode the extension
*/
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
                .encodeList(m_oids)
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input).decodeList(m_oids);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        foreach (oid; m_oids)
            subject.add("X509v3.ExtendedKeyUsage", oid.toString());
    }

    Vector!OID m_oids;
}

/**
* Certificate Policies Extension
*/
final class CertificatePolicies : Certificate_Extension
{
public:
    CertificatePolicies copy() const
    { return new CertificatePolicies(m_oids); }

    this() {}
    this(in Vector!OID o) { m_oids = o; }

    Vector!OID getOids() const { return m_oids; }
private:
    string oidName() const { return "X509v3.CertificatePolicies"; }

    bool shouldEncode() const { return (m_oids.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        Vector!( PolicyInformation ) policies;
        
        foreach (oid; m_oids)
            policies.pushBack(m_oids[i]);
        
        return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
                .encodeList(policies)
                .endCons()
                .getContentsUnlocked();
    }
    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        Vector!( PolicyInformation ) policies;
        
        BERDecoder(input).decodeList(policies);
        
        m_oids.clear();
        foreach (policy; policies)
            m_oids.pushBack(policy.oid);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore info, ref DataStore) const
    {
        foreach (oid; m_oids)
            info.add("X509v3.CertificatePolicies", oid.toString());
    }

    Vector!OID m_oids;
}

final class AuthorityInformationAccess : Certificate_Extension
{
public:
    AuthorityInformationAccess copy() const
    { return new AuthorityInformationAccess(m_ocsp_responder); }

    this() {}

    this(in string ocsp) { m_ocsp_responder = ocsp; }

private:
    string oidName() const { return "PKIX.AuthorityInformationAccess"; }

    bool shouldEncode() const { return (m_ocsp_responder != ""); }

    Vector!ubyte encodeInner() const
    {
        ASN1String url = ASN1String(m_ocsp_responder, IA5_STRING);
        
        return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(OIDS.lookup("PKIX.OCSP"))
                .addObject(ASN1Tag(6), ASN1Tag.CONTEXT_SPECIFIC, url.iso8859())
                .endCons()
                .endCons().getContentsUnlocked();
    }

    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder ber = BERDecoder(input).startCons(ASN1Tag.SEQUENCE);
        
        while (ber.moreItems())
        {
            OID oid;
            
            BERDecoder info = ber.startCons(ASN1Tag.SEQUENCE);
            
            info.decode(oid);
            
            if (oid == OIDS.lookup("PKIX.OCSP"))
            {
                BER_Object name = info.getNextObject();
                
                if (name.type_tag == 6 && name.class_tag == ASN1Tag.CONTEXT_SPECIFIC)
                {
                    m_ocsp_responder = transcode(name.toString(),
                                                 LATIN1_CHARSET,
                                                 LOCAL_CHARSET);
                }
                
            }
        }
    }



    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        if (m_ocsp_responder != "")
            subject.add("OCSP.responder", m_ocsp_responder);
    }

    string m_ocsp_responder;
}


/**
* CRL Number Extension
*/
final class CRLNumber : Certificate_Extension
{
public:
    /*
    * Copy a CRL_Number extension
    */
    CRLNumber copy() const
    {
        if (!m_has_value)
            throw new InvalidState("CRL_Number::copy: Not set");
        return new CRLNumber(m_crl_number);
    }


    this() { m_has_value = false; m_crl_number = 0; }
    this(size_t n) { m_has_value = true; m_crl_number = n; }

    /*
    * Checked accessor for the crl_number member
    */
    size_t getCrlNumber() const
    {
        if (!m_has_value)
            throw new InvalidState("CRL_Number::get_crl_number: Not set");
        return m_crl_number;
    }

private:
    string oidName() const { return "X509v3.CRLNumber"; }

    bool shouldEncode() const { return m_has_value; }
    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_crl_number).getContentsUnlocked();
    }
    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        BERDecoder(input).decode(m_crl_number);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore info, ref DataStore) const
    {
        info.add("X509v3.CRLNumber", m_crl_number);
    }

    bool m_has_value;
    size_t m_crl_number;
}

/**
* CRL Entry Reason Code Extension
*/
final class CRLReasonCode : Certificate_Extension
{
public:
    CRLReasonCode copy() const { return new CRLReasonCode(m_reason); }

    this(CRLCode r = CRL_Code.UNSPECIFIED) { m_reason = r; }

    CRLCode getReason() const { return m_reason; }
private:
    string oidName() const { return "X509v3.ReasonCode"; }

    bool shouldEncode() const { return (m_reason != CRL_Code.UNSPECIFIED); }
    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
            .encode(cast(size_t)(m_reason), ASN1Tag.ENUMERATED, ASN1Tag.UNIVERSAL)
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(in Vector!ubyte input)
    {
        size_t reason_code = 0;
        BERDecoder(input).decode(reason_code, ASN1Tag.ENUMERATED, ASN1Tag.UNIVERSAL);
        m_reason = cast(CRLCode)(reason_code);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore info, ref DataStore) const
    {
        info.add("X509v3.CRLReasonCode", m_reason);
    }

    CRL_Code m_reason;
}


/**
* CRL Distribution Points Extension
*/
final class CRLDistributionPoints : Certificate_Extension
{
public:
    alias DistributionPoint = FreeListRef!DistributionPointImpl;
    final class DistributionPointImpl : ASN1Object
    {
    public:
        void encodeInto(DEREncoder) const
        {
            throw new Exception("CRLDistributionPoints encoding not implemented");
        }

        void decodeFrom(BERDecoder ber)
        {
            ber.startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag(0), ASN1Tag.CONTEXT_SPECIFIC)
                    .decodeOptionalImplicit(m_point, ASN1Tag(0),
                                              ASN1Tag(ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED),
                                              ASN1Tag.SEQUENCE, ASN1Tag.CONSTRUCTED)
                    .endCons().endCons();
        }


        AlternativeName point() const { return m_point; }
    private:
        AlternativeName m_point;
    }

    CRLDistributionPoints copy() const
    { return new CRLDistributionPoints(m_distribution_points); }

    this() {}

    this(in Vector!( DistributionPoint ) points) { m_distribution_points = points; }

    Vector!( DistributionPoint ) distributionPoints() const
    { return m_distribution_points; }

private:
    string oidName() const { return "X509v3.CRLDistributionPoints"; }

    bool shouldEncode() const { return !m_distribution_points.empty; }

    Vector!ubyte encodeInner() const
    {
        throw new Exception("CRLDistributionPoints encoding not implemented");
    }

    void decodeInner(in Vector!ubyte buf)
    {
        BERDecoder(buf).decodeList(m_distribution_points).verifyEnd();
    }


    void contentsTo(ref DataStore info, ref DataStore) const
    {
        foreach (distribution_point; m_distribution_points)
        {
            auto point = distribution_point.point().contents();
            
            point.equalRange("URI", (string val) {
                info.add("CRL.DistributionPoint", val);
            });
        }
    }

    Vector!( DistributionPoint ) m_distribution_points;
}


alias PolicyInformation = FreeListRef!PolicyInformationImpl;

/*
* A policy specifier
*/
final class PolicyInformationImpl : ASN1Object
{
public:
    OID oid;
    
    this() {}
    this(in OID oid_) { oid = oid_; }
    
    void encodeInto(DEREncoder codec) const
    {
        codec.startCons(ASN1Tag.SEQUENCE)
            .encode(oid)
                .endCons();
    }
    
    void decodeFrom(BERDecoder codec)
    {
        codec.startCons(ASN1Tag.SEQUENCE)
            .decode(oid)
                .discardRemaining()
                .endCons();
    }
}
