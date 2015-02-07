/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.x509_key;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_X509_CERTIFICATES):

alias x509_key = botan.pubkey.x509_key;

public import botan.pubkey.pk_keys;
public import botan.asn1.alg_id;
public import botan.filters.pipe;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.codec.pem;
import botan.pubkey.pk_algs;
import botan.utils.types;

alias X509Encoding = bool;
/**
* The two types of X509 encoding supported by Botan.
*/
enum : X509Encoding { RAW_BER, PEM_ }

/**
* BER encode a key
* @param key = the public key to encode
* @return BER encoding of this key
*/
Vector!ubyte BER_encode(in PublicKey key)
{
    return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
            .encode(key.algorithmIdentifier())
            .encode(key.x509SubjectPublicKey(), ASN1Tag.BIT_STRING)
            .endCons()
            .getContentsUnlocked();
}

/**
* PEM encode a public key into a string.
* @param key = the key to encode
* @return PEM encoded key
*/
string PEM_encode(in PublicKey key)
{
    return PEM.encode(x509_key.BER_encode(key), "PUBLIC KEY");
}

/**
* Create a public key from a data source.
* @param source = the source providing the DER or PEM encoded key
* @return new public key object
*/
PublicKey loadKey(DataSource source)
{
    try {
		auto alg_id = AlgorithmIdentifier();
        SecureVector!ubyte key_bits;
        
        if (maybeBER(source) && !PEM.matches(source))
        {
            BERDecoder(source)
                    .startCons(ASN1Tag.SEQUENCE)
                    .decode(alg_id)
                    .decode(key_bits, ASN1Tag.BIT_STRING)
                    .verifyEnd()
                    .endCons();
        }
        else
        {
            auto ber = DataSourceMemory(PEM.decodeCheckLabel(source, "PUBLIC KEY"));
            
            BERDecoder(cast(DataSource)ber)
                    .startCons(ASN1Tag.SEQUENCE)
                    .decode(alg_id)
                    .decode(key_bits, ASN1Tag.BIT_STRING)
                    .verifyEnd()
                    .endCons();
        }
        
        if (key_bits.empty)
            throw new DecodingError("X.509 public key decoding failed");
        
        return makePublicKey(alg_id, key_bits);
    }
    catch(DecodingError)
    {
        throw new DecodingError("X.509 public key decoding failed");
    }
}

/**
* Create a public key from a file
* @param filename = pathname to the file to load
* @return new public key object
*/
PublicKey loadKey(in string filename)
{
    auto source = DataSourceStream(filename, true);
    return x509_key.loadKey(cast(DataSource)source);
}


/**
* Create a public key from a memory region.
* @param enc = the memory region containing the DER or PEM encoded key
* @return new public key object
*/
PublicKey loadKey(ALLOC)(auto const ref Vector!(ubyte, ALLOC) enc)
{
    auto source = DataSourceMemory(&enc);
    return x509_key.loadKey(cast(DataSource)source);
}

/**
* Copy a key.
* @param key = the public key to copy
* @return new public key object
*/
PublicKey copyKey(in PublicKey key)
{
    auto source = DataSourceMemory(PEM_encode(key));
    return x509_key.loadKey(cast(DataSource)source);
}

static if (BOTAN_TEST && BOTAN_HAS_X509_CERTIFICATES && BOTAN_HAS_RSA && BOTAN_HAS_DSA):

import botan.test;
import botan.filters.filters;
import botan.rng.auto_rng;
import botan.pubkey.algo.rsa;
import botan.pubkey.algo.dsa;
import botan.pubkey.algo.ecdsa;

import botan.cert.x509.x509self;
import botan.cert.x509.x509path;
import botan.cert.x509.x509_ca;
import botan.asn1.asn1_time;
import botan.cert.x509.pkcs10;

ulong keyId(in PublicKey key)
{
    Pipe pipe = Pipe(new HashFilter("SHA-1", 8));
    pipe.startMsg();
    pipe.write(key.algoName());
    pipe.write(key.algorithmIdentifier().parameters);
    pipe.write(key.x509SubjectPublicKey());
    pipe.endMsg();
    
	SecureVector!ubyte output = pipe.readAll();
    
    if (output.length != 8)
        throw new InternalError("PublicKey::key_id: Incorrect output size");
    
    ulong id = 0;
    for(uint j = 0; j != 8; ++j)
        id = (id << 8) | output[j];
    return id;
}


/* Return some option sets */
X509CertOptions caOpts()
{
    X509CertOptions opts = X509CertOptions("Test CA/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@globecsys.com";
    
    opts.cAKey(1);
    
    return opts;
}

X509CertOptions reqOpts1()
{
    X509CertOptions opts = X509CertOptions("Test User 1/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@globecsys.com";
    
    return opts;
}

X509CertOptions reqOpts2()
{
    X509CertOptions opts = X509CertOptions("Test User 2/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@randombit.net";
    
    opts.addExConstraint("PKIX.EmailProtection");
    
    return opts;
}

uint checkAgainstCopy(const PrivateKey orig, RandomNumberGenerator rng)
{
    PrivateKey copy_priv = pkcs8.copyKey(orig, rng);
    PublicKey copy_pub = x509_key.copyKey(orig);
    
    const string passphrase = "I need work! -Mr. T";
    auto enc_source = DataSourceMemory(pkcs8.PEM_encode(orig, rng, passphrase));
    PrivateKey copy_priv_enc = pkcs8.loadKey(cast(DataSource)enc_source, rng, passphrase);
    
    ulong orig_id = keyId(orig);
    ulong pub_id = keyId(copy_pub);
    ulong priv_id = keyId(copy_priv);
    ulong priv_enc_id = keyId(copy_priv_enc);
    
    delete copy_pub;
    delete copy_priv;
    delete copy_priv_enc;
    
    if (orig_id != pub_id || orig_id != priv_id || orig_id != priv_enc_id)
    {
        logTrace("Failed copy check for " ~ orig.algoName());
        return 1;
    }
    return 0;
}

static if (!SKIP_X509_KEY_TEST) unittest
{
    auto rng = AutoSeededRNG();
    const string hash_fn = "SHA-256";
    
    size_t fails = 0;
    
    /* Create the CA's key and self-signed cert */
    auto ca_key = RSAPrivateKey(rng, 2048);
	logDebug("First CA Cert");
    X509Certificate ca_cert = x509self.createSelfSignedCert(caOpts(), ca_key, hash_fn, rng);
	logDebug(ca_cert.toString());
    /* Create user #1's key and cert request */
    auto user1_key = DSAPrivateKey(rng, DLGroup("dsa/botan/2048"));
    
    PKCS10Request user1_req = x509self.createCertReq(reqOpts1(), user1_key, "SHA-1", rng);
    
    /* Create user #2's key and cert request */
    static if (BOTAN_HAS_ECDSA) {
        ECGroup ecc_domain = ECGroup(OID("1.2.840.10045.3.1.7"));
        auto user2_key = ECDSAPrivateKey(rng, ecc_domain);
    } else static if (BOTAN_HAS_RSA) {
        RSAPrivateKey user2_key = RSAPrivateKey(rng, 1536);
    } else static assert(false, "Must have ECSA or RSA for X509!");
    
	logDebug("user2_req");
    PKCS10Request user2_req = x509self.createCertReq(reqOpts2(), user2_key, hash_fn, rng);
    
    /* Create the CA object */
    X509CA ca = X509CA(ca_cert, ca_key, hash_fn);
    
	logDebug("user1_cert");
    /* Sign the requests to create the certs */
    X509Certificate user1_cert = ca.signRequest(user1_req, rng, X509Time("2008-01-01"), X509Time("2100-01-01"));
    
    X509Certificate user2_cert = ca.signRequest(user2_req, rng, X509Time("2008-01-01"), X509Time("2100-01-01"));
    X509CRL crl1 = ca.newCRL(rng);
    
    /* Verify the certs */
    CertificateStoreInMemory store;
    
    store.addCertificate(ca_cert);
    
    PathValidationRestrictions restrictions = PathValidationRestrictions(false);
    
    PathValidationResult result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (!result_u1.successfulValidation())
    {
        logTrace("FAILED: User cert #1 did not validate - " ~ result_u1.resultString());
        ++fails;
    }
    
    PathValidationResult result_u2 = x509PathValidate(user2_cert, restrictions, store);
    if (!result_u2.successfulValidation())
    {
        logTrace("FAILED: User cert #2 did not validate - " ~ result_u2.resultString());
        ++fails;
    }
    
    store.addCrl(crl1);
    
    Vector!CRLEntry revoked;
    revoked.pushBack(CRLEntry(user1_cert, CESSATION_OF_OPERATION));
    revoked.pushBack(CRLEntry(user2_cert));
    
    X509CRL crl2 = ca.updateCRL(crl1, revoked, rng);
    
    store.addCrl(crl2);
    
    result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (result_u1.result() != CertificateStatusCode.CERT_IS_REVOKED)
    {
        logTrace("FAILED: User cert #1 was not revoked - " ~ result_u1.resultString());
        ++fails;
    }
    
    result_u2 = x509PathValidate(user2_cert, restrictions, store);
    if (result_u2.result() != CertificateStatusCode.CERT_IS_REVOKED)
    {
        logTrace("FAILED: User cert #2 was not revoked - " ~ result_u2.resultString());
        ++fails;
    }
    
    revoked.clear();
    revoked.pushBack(CRLEntry(user1_cert, REMOVE_FROM_CRL));
    X509CRL crl3 = ca.updateCRL(crl2, revoked, rng);
    
    store.addCrl(crl3);
    
    result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (!result_u1.successfulValidation())
    {
        logTrace("FAILED: User cert #1 was not un-revoked - " ~ result_u1.resultString());
        ++fails;
    }
    
    checkAgainstCopy(ca_key, rng);
    checkAgainstCopy(user1_key, rng);
    checkAgainstCopy(user2_key, rng);

    testReport("X509_key", 5, fails);
}