/*
* X.509 Certificate Authority
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_ca;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

public import botan.cert.x509.crl_ent;
import botan.asn1.asn1_time;
import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.cert.x509.x509_ext;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.cert.x509.pkcs10;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.libstate.lookup;
import botan.asn1.oids;
import botan.cert.x509.key_constraint;
import botan.rng.rng;
import std.datetime;
import std.algorithm;

/**
* This class represents X.509 Certificate Authorities (CAs).
*/
struct X509CA
{
public:

    /**
    * Sign a PKCS#10 Request.
    * @param req = the request to sign
    * @param rng = the rng to use
    * @param not_before = the starting time for the certificate
    * @param not_after = the expiration time for the certificate
    * @return resulting certificate
    */
    X509Certificate signRequest(in PKCS10Request req,
                                  RandomNumberGenerator rng,
                                  in X509Time not_before,
                                  in X509Time not_after)
    {
        KeyConstraints constraints;
        if (req.isCA())
            constraints = KeyConstraints.KEY_CERT_SIGN | KeyConstraints.CRL_SIGN;
        else
        {
            Unique!PublicKey key = req.subjectPublicKey();
            constraints = findConstraints(*key, req.constraints());
        }

        X509Extensions extensions;
        
        extensions.add(new BasicConstraints(req.isCA(), req.pathLimit()), true);
        
        extensions.add(new KeyUsage(constraints), true);
        
        extensions.add(new AuthorityKeyID(m_cert.subjectKeyId().dup));
        extensions.add(new SubjectKeyID(req.rawPublicKey().dup));
        
        extensions.add(new SubjectAlternativeName(req.subjectAltName()));
        
        extensions.add(new ExtendedKeyUsage(req.exConstraints()));
        
        return makeCert(m_signer, rng, m_ca_sig_algo,
                         req.rawPublicKey(),
                         not_before, not_after,
                         m_cert.subjectDn(), req.subjectDn(),
                         extensions);
    }

    /**
    * Get the certificate of this CA.
    * @return CA certificate
    */
    const(X509Certificate) caCertificate() const
    {
        return m_cert;
    }

    /**
    * Create a new and empty CRL for this CA.
    * @param rng = the random number generator to use
    * @param next_update = the time to set in next update in seconds
    * as the offset from the current time
    * @return new CRL
    */
    X509CRL newCRL(RandomNumberGenerator rng, Duration next_update = 0.seconds) const
    {
        Vector!CRLEntry empty;
        return makeCRL(empty, 1, next_update, rng);
    }

    /**
    * Create a new CRL by with additional entries.
    * @param last_crl = the last CRL of this CA to add the new entries to
    * @param new_entries = contains the new CRL entries to be added to the CRL
    * @param rng = the random number generator to use
    * @param next_update = the time to set in next update in seconds
    * as the offset from the current time
    */
    X509CRL updateCRL()(in X509CRL crl,
                        auto const ref Vector!CRLEntry new_revoked,
                        RandomNumberGenerator rng,
                        Duration next_update = 0.seconds) const
    {

        Vector!CRLEntry revoked = crl.getRevoked().dup;
		revoked ~= new_revoked[];
        return makeCRL(revoked, crl.crlNumber() + 1, next_update, rng);
    }


    /**
    * Interface for creating new certificates
    * @param signer = a signing object
    * @param rng = a random number generator
    * @param sig_algo = the signature algorithm identifier
    * @param pub_key = the serialized public key
    * @param not_before = the start time of the certificate
    * @param not_after = the end time of the certificate
    * @param issuer_dn = the DN of the issuer
    * @param subject_dn = the DN of the subject
    * @param extensions = an optional list of certificate extensions
    * @returns newly minted certificate
    */
    static X509Certificate makeCert(int ALLOC)(ref PKSigner signer,
			                                    RandomNumberGenerator rng,
			                                    in AlgorithmIdentifier sig_algo,
			                                    auto const ref Vector!(ubyte, ALLOC) pub_key,
			                                    in X509Time not_before,
			                                    in X509Time not_after,
			                                    in X509DN issuer_dn,
			                                    in X509DN subject_dn,
			                                    in X509Extensions extensions)
    {
        __gshared immutable size_t X509_CERT_VERSION = 3;
        __gshared immutable size_t SERIAL_BITS = 128;
        
        BigInt serial_no = BigInt(rng, SERIAL_BITS);
        
        Vector!ubyte cert = X509Object.makeSigned(
            signer, rng, sig_algo,
            DEREncoder().startCons(ASN1Tag.SEQUENCE)
            .startExplicit(0)
            .encode(X509_CERT_VERSION-1)
            .endExplicit()
            
            .encode(serial_no)
            
            .encode(sig_algo)
            .encode(issuer_dn)
            
            .startCons(ASN1Tag.SEQUENCE)
            .encode(not_before)
            .encode(not_after)
            .endCons()
            
            .encode(subject_dn)
            .rawBytes(pub_key)
            
            .startExplicit(3)
            .startCons(ASN1Tag.SEQUENCE)
            .encode(extensions)
            .endCons()
            .endExplicit()
            .endCons()
            .getContents());
        
        return X509Certificate(cert.move);
    }

    /**
    * Create a new CA object. Load the certificate and private key
    * @param ca_certificate = the certificate of the CA
    * @param key = the private key of the CA
    * @param hash_fn = name of a hash function to use for signing
    */
    this(X509Certificate c,
         in PrivateKey key,
         in string hash_fn)
    {
        m_cert = c;
        if (!m_cert.isCACert())
            throw new InvalidArgument("X509_CA: This certificate is not for a CA");
        
        m_signer = chooseSigFormat(key, hash_fn, m_ca_sig_algo);
    }

    /*
    * X509_CA Destructor
    */
    ~this()
    {
    }
private:
    /*
    * Create a CRL
    */
    X509CRL makeCRL(const ref Vector!CRLEntry revoked,
                    uint crl_number, Duration next_update,
                    RandomNumberGenerator rng) const
    {
        __gshared immutable size_t X509_CRL_VERSION = 2;
        
        if (next_update == 0.seconds)
            next_update = 7.days;
        
        // Totally stupid: ties encoding logic to the return of std::time!!
        auto current_time = Clock.currTime();
        auto expire_time = current_time + next_update;
        
        X509Extensions extensions;
        extensions.add(new AuthorityKeyID(m_cert.subjectKeyId().dup));
        extensions.add(new CRLNumber(crl_number));
        PKSigner* _signer = cast(PKSigner*)&m_signer;
        Vector!ubyte crl = X509Object.makeSigned(
            *_signer, rng, m_ca_sig_algo,
            DEREncoder().startCons(ASN1Tag.SEQUENCE)
            .encode(X509_CRL_VERSION-1)
            .encode(m_ca_sig_algo)
            .encode(m_cert.issuerDn())
            .encode(X509Time(current_time))
            .encode(X509Time(expire_time))
            .encodeIf (revoked.length > 0,
                    DEREncoder()
                    .startCons(ASN1Tag.SEQUENCE)
                    .encodeList(revoked)
                    .endCons()
                    )
            .startExplicit(0)
            .startCons(ASN1Tag.SEQUENCE)
            .encode(extensions)
            .endCons()
            .endExplicit()
            .endCons()
            .getContents());
        
        return X509CRL(crl.move);
    }    


    AlgorithmIdentifier m_ca_sig_algo;
    X509Certificate m_cert;
    PKSigner m_signer;
}

/**
* Choose the default signature format for a certain public key signature
* scheme.
* @param key = will be the key to choose a padding scheme for
* @param hash_fn = is the desired hash function
* @param alg_id = will be set to the chosen scheme
* @return A PKSigner object for generating signatures
*/
/*
* Choose a signing format for the key
*/
PKSigner chooseSigFormat(in PrivateKey key,
                            in string hash_fn,
                            AlgorithmIdentifier sig_algo)
{
    import std.array : Appender;
    Appender!string padding;
    
    const string algo_name = key.algoName;
    
    const HashFunction proto_hash = retrieveHash(hash_fn);
    if (!proto_hash)
        throw new AlgorithmNotFound(hash_fn);
    
    if (key.maxInputBits() < proto_hash.outputLength*8)
        throw new InvalidArgument("Key is too small for chosen hash function");
    
    if (algo_name == "RSA")
        padding ~= "EMSA3";
    else if (algo_name == "DSA")
        padding ~= "EMSA1";
    else if (algo_name == "ECDSA")
        padding ~= "EMSA1_BSI";
    else
        throw new InvalidArgument("Unknown X.509 signing key type: " ~ algo_name);
    
    SignatureFormat format = (key.messageParts() > 1) ? DER_SEQUENCE : IEEE_1363;

    padding ~= padding.data ~ '(' ~ proto_hash.name ~ ')';
    
    sig_algo.oid = OIDS.lookup(algo_name ~ "/" ~ padding.data);
    sig_algo.parameters = key.algorithmIdentifier().parameters;
    
    return PKSigner(key, padding.data, format);
}