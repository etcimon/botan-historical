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
enum X509_Encoding { RAW_BER, PEM }

/**
* BER encode a key
* @param key = the public key to encode
* @return BER encoding of this key
*/
Vector!ubyte BER_encode(in Public_Key key)
{
    return DER_Encoder()
            .start_cons(ASN1_Tag.SEQUENCE)
            .encode(key.algorithm_identifier())
            .encode(key.x509_subject_public_key(), ASN1_Tag.BIT_STRING)
            .end_cons()
            .get_contents_unlocked();
}

/**
* PEM encode a public key into a string.
* @param key = the key to encode
* @return PEM encoded key
*/
string PEM_encode(in Public_Key key)
{
    return PEM.encode(x509_key.BER_encode(key), "PUBLIC KEY");
}

/**
* Create a public key from a data source.
* @param source = the source providing the DER or PEM encoded key
* @return new public key object
*/
Public_Key load_key(DataSource source)
{
    try {
        Algorithm_Identifier alg_id;
        Secure_Vector!ubyte key_bits;
        
        if (maybe_BER(source) && !PEM.matches(source))
        {
            BER_Decoder(source)
                    .start_cons(ASN1_Tag.SEQUENCE)
                    .decode(alg_id)
                    .decode(key_bits, ASN1_Tag.BIT_STRING)
                    .verify_end()
                    .end_cons();
        }
        else
        {
            auto ber = scoped!DataSource_Memory(PEM.decode_check_label(source, "PUBLIC KEY"));
            
            BER_Decoder(ber)
                    .start_cons(ASN1_Tag.SEQUENCE)
                    .decode(alg_id)
                    .decode(key_bits, ASN1_Tag.BIT_STRING)
                    .verify_end()
                    .end_cons();
        }
        
        if (key_bits.empty)
            throw new Decoding_Error("X.509 public key decoding failed");
        
        return make_public_key(alg_id, key_bits);
    }
    catch(Decoding_Error)
    {
        throw new Decoding_Error("X.509 public key decoding failed");
    }
}

/**
* Create a public key from a file
* @param filename = pathname to the file to load
* @return new public key object
*/
Public_Key load_key(in string filename)
{
    auto source = scoped!DataSource_Stream(filename, true);
    return x509_key.load_key(source);
}


/**
* Create a public key from a memory region.
* @param enc = the memory region containing the DER or PEM encoded key
* @return new public key object
*/
Public_Key load_key(in Vector!ubyte enc)
{
    auto source = scoped!DataSource_Memory(enc);
    return x509_key.load_key(source);
}

/**
* Copy a key.
* @param key = the public key to copy
* @return new public key object
*/
Public_Key copy_key(in Public_Key key)
{
    auto source = scoped!DataSource_Memory(PEM_encode(key));
    return x509_key.load_key(source);
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

ulong key_id(const Public_Key* key)
{
    Pipe pipe = Pipe(new Hash_Filter("SHA-1", 8));
    pipe.start_msg();
    pipe.write(key.algo_name());
    pipe.write(key.algorithm_identifier().parameters);
    pipe.write(key.x509_subject_public_key());
    pipe.end_msg();
    
    Secure_Vector!ubyte output = pipe.read_all();
    
    if (output.length != 8)
        throw new Internal_Error("Public_Key::key_id: Incorrect output size");
    
    ulong id = 0;
    for(uint j = 0; j != 8; ++j)
        id = (id << 8) | output[j];
    return id;
}


/* Return some option sets */
X509_Cert_Options ca_opts()
{
    X509_Cert_Options opts = X509_Cert_Options("Test CA/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@randombit.net";
    
    opts.CA_key(1);
    
    return opts;
}

X509_Cert_Options req_opts1()
{
    X509_Cert_Options opts = X509_Cert_Options("Test User 1/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@randombit.net";
    
    return opts;
}

X509_Cert_Options req_opts2()
{
    X509_Cert_Options opts = X509_Cert_Options("Test User 2/US/Botan Project/Testing");
    
    opts.uri = "http://botan.randombit.net";
    opts.dns = "botan.randombit.net";
    opts.email = "testing@randombit.net";
    
    opts.add_ex_constraint("PKIX.EmailProtection");
    
    return opts;
}

uint check_against_copy(const Private_Key orig, RandomNumberGenerator rng)
{
    Private_Key copy_priv = pkcs8.copy_key(orig, rng);
    Public_Key copy_pub = x509_key.copy_key(orig);
    
    const string passphrase = "I need work! -Mr. T";
    DataSource_Memory enc_source = pkcs8.PEM_encode(orig, rng, passphrase);
    Private_Key copy_priv_enc = pkcs8.load_key(enc_source, rng, passphrase);
    
    ulong orig_id = key_id(&orig);
    ulong pub_id = key_id(copy_pub);
    ulong priv_id = key_id(copy_priv);
    ulong priv_enc_id = key_id(copy_priv_enc);
    
    delete copy_pub;
    delete copy_priv;
    delete copy_priv_enc;
    
    if (orig_id != pub_id || orig_id != priv_id || orig_id != priv_enc_id)
    {
        writeln("Failed copy check for " ~ orig.algo_name());
        return 1;
    }
    return 0;
}

unittest
{
    AutoSeeded_RNG rng;
    const string hash_fn = "SHA-256";
    
    size_t fails = 0;
    
    /* Create the CA's key and self-signed cert */
    auto ca_key = scoped!RSA_PrivateKey(rng, 2048);
    
    X509_Certificate ca_cert = x509self.create_self_signed_cert(ca_opts(), ca_key, hash_fn, rng);
    /* Create user #1's key and cert request */
    auto user1_key = scoped!DSA_PrivateKey(rng, DL_Group("dsa/botan/2048"));
    
    PKCS10_Request user1_req = x509self.create_cert_req(req_opts1(), user1_key, "SHA-1", rng);
    
    /* Create user #2's key and cert request */
    static if (BOTAN_HAS_ECDSA) {
        EC_Group ecc_domain = EC_Group(OID("1.2.840.10045.3.1.7"));
        auto user2_key = scoped!ECDSA_PrivateKey(rng, ecc_domain);
    } else static if (BOTAN_HAS_RSA) {
        RSA_PrivateKey user2_key = scoped!RSA_PrivateKey(rng, 1536);
    } else static assert(false, "Must have ECSA or RSA for X509!");
    
    PKCS10_Request user2_req = x509self.create_cert_req(req_opts2(), user2_key, hash_fn, rng);
    
    /* Create the CA object */
    X509_CA ca = X509_CA(ca_cert, ca_key, hash_fn);
    
    /* Sign the requests to create the certs */
    X509_Certificate user1_cert = ca.sign_request(user1_req, rng, X509_Time("2008-01-01"), X509_Time("2100-01-01"));
    
    X509_Certificate user2_cert = ca.sign_request(user2_req, rng, X509_Time("2008-01-01"), X509_Time("2100-01-01"));
    X509_CRL crl1 = ca.new_crl(rng);
    
    /* Verify the certs */
    Certificate_Store_In_Memory store;
    
    store.add_certificate(ca_cert);
    
    Path_Validation_Restrictions restrictions = Path_Validation_Restrictions(false);
    
    Path_Validation_Result result_u1 = x509_path_validate(user1_cert, restrictions, store);
    if (!result_u1.successful_validation())
    {
        writeln("FAILED: User cert #1 did not validate - " ~ result_u1.result_string());
        ++fails;
    }
    
    Path_Validation_Result result_u2 = x509_path_validate(user2_cert, restrictions, store);
    if (!result_u2.successful_validation())
    {
        writeln("FAILED: User cert #2 did not validate - " ~ result_u2.result_string());
        ++fails;
    }
    
    store.add_crl(crl1);
    
    Vector!CRL_Entry revoked;
    revoked.push_back(CRL_Entry(user1_cert, CESSATION_OF_OPERATION));
    revoked.push_back(user2_cert);
    
    X509_CRL crl2 = ca.update_crl(crl1, revoked, rng);
    
    store.add_crl(crl2);
    
    result_u1 = x509_path_validate(user1_cert, restrictions, store);
    if (result_u1.result() != Certificate_Status_Code.CERT_IS_REVOKED)
    {
        writeln("FAILED: User cert #1 was not revoked - " ~ result_u1.result_string());
        ++fails;
    }
    
    result_u2 = x509_path_validate(user2_cert, restrictions, store);
    if (result_u2.result() != Certificate_Status_Code.CERT_IS_REVOKED)
    {
        writeln("FAILED: User cert #2 was not revoked - " ~ result_u2.result_string());
        ++fails;
    }
    
    revoked.clear();
    revoked.push_back(CRL_Entry(user1_cert, REMOVE_FROM_CRL));
    X509_CRL crl3 = ca.update_crl(crl2, revoked, rng);
    
    store.add_crl(crl3);
    
    result_u1 = x509_path_validate(user1_cert, restrictions, store);
    if (!result_u1.successful_validation())
    {
        writeln("FAILED: User cert #1 was not un-revoked - " ~ result_u1.result_string());
        ++fails;
    }
    
    check_against_copy(ca_key, rng);
    check_against_copy(user1_key, rng);
    check_against_copy(user2_key, rng);

    test_report("X509_key", 5, fails);
}