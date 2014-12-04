/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.x509_key;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

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

// import string;
/**
* The two types of X509 encoding supported by Botan.
*/
enum X509Encoding { RAW_BER, PEM }

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
        AlgorithmIdentifier alg_id;
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
            auto ber = scoped!DataSourceMemory(PEM.decodeCheckLabel(source, "PUBLIC KEY"));
            
            BERDecoder(ber)
                    .startCons(ASN1Tag.SEQUENCE)
                    .decode(alg_id)
                    .decode(key_bits, ASN1Tag.BIT_STRING)
                    .verifyEnd()
                    .endCons();
        }
        
        if (key_bits.empty)
            throw new DecodingError("X.509 public key decoding failed");
        
        return make_public_key(alg_id, key_bits);
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
    auto source = scoped!DataSourceStream(filename, true);
    return x509_key.loadKey(source);
}


/**
* Create a public key from a memory region.
* @param enc = the memory region containing the DER or PEM encoded key
* @return new public key object
*/
PublicKey loadKey(in Vector!ubyte enc)
{
    auto source = scoped!DataSourceMemory(enc);
    return x509_key.loadKey(source);
}

/**
* Copy a key.
* @param key = the public key to copy
* @return new public key object
*/
PublicKey copyKey(in PublicKey key)
{
    auto source = scoped!DataSourceMemory(PEM_encode(key));
    return x509_key.loadKey(source);
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
import botan.cert.x509.pkcs10;

ulong keyId(const PublicKey* key)
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
    X509_Cert_Options opts = X509_Cert_Options("Test CA/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@globecsys.com";
    
    opts.cAKey(1);
    
    return opts;
}

X509CertOptions reqOpts1()
{
    X509_Cert_Options opts = X509_Cert_Options("Test User 1/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@globecsys.com";
    
    return opts;
}

X509CertOptions reqOpts2()
{
    X509_Cert_Options opts = X509_Cert_Options("Test User 2/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@randombit.net";
    
    opts.addExConstraint("PKIX.EmailProtection");
    
    return opts;
}

uint checkAgainstCopy(const PrivateKey orig, RandomNumberGenerator rng)
{
    PrivateKey copy_priv = pkcs8.copy_key(orig, rng);
    PublicKey copy_pub = x509_key.copy_key(orig);
    
    const string passphrase = "I need work! -Mr. T";
    DataSourceMemory enc_source = pkcs8.PEM_encode(orig, rng, passphrase);
    PrivateKey copy_priv_enc = pkcs8.loadKey(enc_source, rng, passphrase);
    
    ulong orig_id = keyId(&orig);
    ulong pub_id = keyId(copy_pub);
    ulong priv_id = keyId(copy_priv);
    ulong priv_enc_id = keyId(copy_priv_enc);
    
    delete copy_pub;
    delete copy_priv;
    delete copy_priv_enc;
    
    if (orig_id != pub_id || orig_id != priv_id || orig_id != priv_enc_id)
    {
        writeln("Failed copy check for " ~ orig.algoName());
        return 1;
    }
    return 0;
}

unittest
{
    AutoSeededRNG rng;
    const string hash_fn = "SHA-256";
    
    size_t fails = 0;
    
    /* Create the CA's key and self-signed cert */
    auto ca_key = scoped!RSAPrivateKey(rng, 2048);
    
    X509Certificate ca_cert = x509self.createSelfSignedCert(caOpts(), ca_key, hash_fn, rng);
    /* Create user #1's key and cert request */
    auto user1_key = scoped!DSAPrivateKey(rng, DLGroup("dsa/botan/2048"));
    
    PKCS10Request user1_req = x509self.createCertReq(req_opts1(), user1_key, "SHA-1", rng);
    
    /* Create user #2's key and cert request */
    static if (BOTAN_HAS_ECDSA) {
        ECGroup ecc_domain = ECGroup(OID("1.2.840.10045.3.1.7"));
        auto user2_key = scoped!ECDSAPrivateKey(rng, ecc_domain);
    } else static if (BOTAN_HAS_RSA) {
        RSAPrivateKey user2_key = scoped!RSAPrivateKey(rng, 1536);
    } else static assert(false, "Must have ECSA or RSA for X509!");
    
    PKCS10Request user2_req = x509self.createCertReq(req_opts2(), user2_key, hash_fn, rng);
    
    /* Create the CA object */
    X509_CA ca = X509_CA(ca_cert, ca_key, hash_fn);
    
    /* Sign the requests to create the certs */
    X509Certificate user1_cert = ca.signRequest(user1_req, rng, X509Time("2008-01-01"), X509Time("2100-01-01"));
    
    X509Certificate user2_cert = ca.signRequest(user2_req, rng, X509Time("2008-01-01"), X509Time("2100-01-01"));
    X509CRL crl1 = ca.newCRL(rng);
    
    /* Verify the certs */
    CertificateStoreInMemory store;
    
    store.addCertificate(ca_cert);
    
    Path_Validation_Restrictions restrictions = Path_Validation_Restrictions(false);
    
    Path_Validation_Result result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (!result_u1.successfulValidation())
    {
        writeln("FAILED: User cert #1 did not validate - " ~ result_u1.resultString());
        ++fails;
    }
    
    Path_Validation_Result result_u2 = x509PathValidate(user2_cert, restrictions, store);
    if (!result_u2.successfulValidation())
    {
        writeln("FAILED: User cert #2 did not validate - " ~ result_u2.resultString());
        ++fails;
    }
    
    store.addCrl(crl1);
    
    Vector!CRLEntry revoked;
    revoked.pushBack(CRLEntry(user1_cert, CESSATION_OF_OPERATION));
    revoked.pushBack(user2_cert);
    
    X509CRL crl2 = ca.updateCRL(crl1, revoked, rng);
    
    store.addCrl(crl2);
    
    result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (result_u1.result() != Certificate_Status_Code.CERT_IS_REVOKED)
    {
        writeln("FAILED: User cert #1 was not revoked - " ~ result_u1.resultString());
        ++fails;
    }
    
    result_u2 = x509PathValidate(user2_cert, restrictions, store);
    if (result_u2.result() != Certificate_Status_Code.CERT_IS_REVOKED)
    {
        writeln("FAILED: User cert #2 was not revoked - " ~ result_u2.resultString());
        ++fails;
    }
    
    revoked.clear();
    revoked.pushBack(CRLEntry(user1_cert, REMOVE_FROM_CRL));
    X509CRL crl3 = ca.updateCRL(crl2, revoked, rng);
    
    store.addCrl(crl3);
    
    result_u1 = x509PathValidate(user1_cert, restrictions, store);
    if (!result_u1.successfulValidation())
    {
        writeln("FAILED: User cert #1 was not un-revoked - " ~ result_u1.resultString());
        ++fails;
    }
    
    check_against_copy(ca_key, rng);
    check_against_copy(user1_key, rng);
    check_against_copy(user2_key, rng);

    testReport("X509_key", 5, fails);
}