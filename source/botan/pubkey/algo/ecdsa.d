/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*             Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecdsa;

import botan.constants;

static if (BOTAN_HAS_ECDSA):

import botan.pubkey.algo.ecc_key;
import botan.math.numbertheory.reducer;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.keypair;
import botan.math.ec_gfp.point_gfp;
import botan.rng.rng;
import botan.utils.types;

/**
* This class represents ECDSA Public Keys.
*/
class ECDSA_PublicKey : EC_PublicKey
{
public:

    /**
    * Construct a public key from a given public point.
    * @param dom_par the domain parameters associated with this key
    * @param public_point the public point defining this key
    */
    this(in EC_Group dom_par, in PointGFp public_point) 
    {
        super(dom_par, public_point);
    }

    this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits)
    {
        super(alg_id, key_bits);
    }

    /**
    * Get this keys algorithm name.
    * @result this keys algorithm name ("ECDSA")
    */
    @property string algo_name() const { return "ECDSA"; }

    /**
    * Get the maximum number of bits allowed to be fed to this key.
    * This is the bitlength of the order of the base point.
    * @result the maximum number of input bits
    */
    size_t max_input_bits() const { return domain().get_order().bits(); }

    size_t message_parts() const { return 2; }

    size_t message_part_size() const
    { return domain().get_order().bytes(); }

protected:
    this() {}
}

/**
* This class represents ECDSA Private Keys
*/
final class ECDSA_PrivateKey : ECDSA_PublicKey,
                               EC_PrivateKey
{
public:

    /**
    * Load a private key
    * @param alg_id the X.509 algorithm identifier
    * @param key_bits PKCS #8 structure
    */
    this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits)
    {
        super(alg_id, key_bits);
    }

    /**
    * Generate a new private key
    * @param rng a random number generator
    * @param domain parameters to used for this key
    * @param x the private key (if zero, generate a ney random key)
    */
    this(RandomNumberGenerator rng, in EC_Group domain, in BigInt x = 0)
    {
        super(rng, domain, x);
    }

    bool check_key(RandomNumberGenerator rng, bool strong) const
    {
        if (!public_point().on_the_curve())
            return false;
        
        if (!strong)
            return true;
        
        return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
    }
}

/**
* ECDSA signature operation
*/
final class ECDSA_Signature_Operation : Signature
{
public:
    this(in ECDSA_PrivateKey ecdsa)
    {
        m_base_point = ecdsa.domain().get_base_point();
        m_order = ecdsa.domain().get_order();
        m_x = ecdsa.private_value();
        m_mod_order = order;
    }

    Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.add_entropy(msg, msg_len);
        
        BigInt m = BigInt(msg, msg_len);
        
        BigInt r = 0, s = 0;
        
        while (r == 0 || s == 0)
        {
            // This contortion is necessary for the tests
            BigInt k;
            k.randomize(rng, m_order.bits());
            
            while (k >= m_order)
                k.randomize(rng, m_order.bits() - 1);
            
            PointGFp k_times_P = m_base_point * k;
            r = m_mod_order.reduce(k_times_P.get_affine_x());
            s = m_mod_order.multiply(inverse_mod(k, m_order), mul_add(m_x, r, m));
        }
        
        Secure_Vector!ubyte output = Secure_Vector!ubyte(2*m_order.bytes());
        r.binary_encode(&output[output.length / 2 - r.bytes()]);
        s.binary_encode(&output[output.length - s.bytes()]);
        return output;
    }

    size_t message_parts() const { return 2; }
    size_t message_part_size() const { return m_order.bytes(); }
    size_t max_input_bits() const { return m_order.bits(); }

private:
    const PointGFp m_base_point;
    const BigInt m_order;
    const BigInt m_x;
    Modular_Reducer m_mod_order;
}

/**
* ECDSA verification operation
*/
final class ECDSA_Verification_Operation : Verification
{
public:
    this(in ECDSA_PublicKey ecdsa) 
    {
        m_base_point = ecdsa.domain().get_base_point();
        m_public_point = ecdsa.public_point();
        m_order = ecdsa.domain().get_order();
    }

    size_t message_parts() const { return 2; }
    size_t message_part_size() const { return m_order.bytes(); }
    size_t max_input_bits() const { return m_order.bits(); }

    bool with_recovery() const { return false; }

    bool verify(in ubyte* msg, size_t msg_len,
                in ubyte* sig, size_t sig_len)
    {
        if (sig_len != m_order.bytes()*2)
            return false;
        
        BigInt e = BigInt(msg, msg_len);
        
        BigInt r = BigInt(sig, sig_len / 2);
        BigInt s = BigInt(sig + sig_len / 2, sig_len / 2);
        
        if (r <= 0 || r >= m_order || s <= 0 || s >= m_order)
            return false;
        
        BigInt w = inverse_mod(s, m_order);
        
        PointGFp R = w * multi_exponentiate(m_base_point, e, m_public_point, r);
        
        if (R.is_zero())
            return false;
        
        return (R.get_affine_x() % m_order == r);
    }

private:
    const PointGFp m_base_point;
    const PointGFp m_public_point;
    const BigInt m_order;
}

static if (BOTAN_TEST):

/******************************************************
* ECDSA tests                                          *
*                                                      *
* (C) 2007 Falko Strenzke                               *
*             Manuel Hartl                              *
*      2008 Jack Lloyd                                  *
******************************************************/

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
static if (BOTAN_HAS_RSA) import botan.pubkey.algo.rsa;
import botan.cert.x509.x509cert;
import botan.asn1.oids;
import botan.utils.memory.memory;
import botan.codec.hex;
import core.atomic;
private __gshared size_t total_tests;

string to_hex(const Vector!ubyte bin)
{
    return hex_encode(&bin[0], bin.length);
}

/**

* Tests whether the the signing routine will work correctly input case
* the integer e that is constructed from the message (thus the hash
* value) is larger than n, the order of the base point.  Tests the
* signing function of the pk signer object */

size_t test_hash_larger_than_n(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    EC_Group dom_pars = EC_Group(OID("1.3.132.0.8")); // secp160r1
    // n = 0x0100000000000000000001f4c8f927aed3ca752257 (21 bytes)
    // . shouldn't work with SHA224 which outputs 28 bytes
    
    size_t fails = 0;
    auto priv_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    
    Vector!ubyte message = Vector!ubyte(20);
    for(size_t i = 0; i != message.length; ++i)
        message[i] = i;
    
    PK_Signer pk_signer_160 = PK_Signer(priv_key, "EMSA1_BSI(SHA-1)");
    PK_Verifier pk_verifier_160 = PK_Verifier(priv_key, "EMSA1_BSI(SHA-1)");
    
    PK_Signer pk_signer_224 = PK_Signer(priv_key, "EMSA1_BSI(SHA-224)");
    
    // Verify we can sign and verify with SHA-160
    Vector!ubyte signature_160 = pk_signer_160.sign_message(message, rng);
    
    mixin( CHECK(` pk_verifier_160.verify_message(message, signature_160) `) );
    
    bool signature_failed = false;
    try
    {
        Vector!ubyte signature_224 = pk_signer_224.sign_message(message, rng);
    }
    catch(Encoding_Error)
    {
        signature_failed = true;
    }
    
    mixin( CHECK(`  signature_failed `) );
    
    // now check that verification alone fails
    
    // sign it with the normal EMSA1
    PK_Signer pk_signer = PK_Signer(priv_key, "EMSA1(SHA-224)");
    Vector!ubyte signature = pk_signer.sign_message(message, rng);
    
    PK_Verifier pk_verifier = PK_Verifier(priv_key, "EMSA1_BSI(SHA-224)");
    
    // verify against EMSA1_BSI
    if (pk_verifier.verify_message(message, signature))
    {
        writeln("Corrupt ECDSA signature verified, should not have");
        ++fails;
    }
    
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t test_decode_ecdsa_X509()
{
    atomicOp!"+="(total_tests, 5);
    X509_Certificate cert = X509_Certificate("test_data/ecc/CSCA.CSCA.csca-germany.1.crt");
    size_t fails = 0;
    
    mixin( CHECK_MESSAGE( OIDS.lookup(cert.signature_algorithm().oid) == "ECDSA/EMSA1(SHA-224)", "error reading signature algorithm from x509 ecdsa certificate" ) );
    
    mixin( CHECK_MESSAGE( to_hex(cert.serial_number()) == "01", "error reading serial from x509 ecdsa certificate" ) );
    mixin( CHECK_MESSAGE( to_hex(cert.authority_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading authority key id from x509 ecdsa certificate" ) );
    mixin( CHECK_MESSAGE( to_hex(cert.subject_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading Subject key id from x509 ecdsa certificate" ) );
    
    Unique!X509_PublicKey pubkey = cert.subject_public_key();
    bool ver_ec = cert.check_signature(*pubkey);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct selfsigned x509-ecdsa certificate" ) );
    
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t test_decode_ver_link_SHA256()
{
    atomicOp!"+="(total_tests, 1);
    X509_Certificate root_cert = X509_Certificate("test_data/ecc/root2_SHA256.cer");
    X509_Certificate link_cert = X509_Certificate("test_data/ecc/link_SHA256.cer");
    
    size_t fails = 0;
    Unique!X509_PublicKey pubkey = root_cert.subject_public_key();
    bool ver_ec = link_cert.check_signature(*pubkey);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct SHA256 link x509-ecdsa certificate" ) );
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t test_decode_ver_link_SHA1()
{
    atomicOp!"+="(total_tests, 1);
    X509_Certificate root_cert = X509_Certificate("test_data/ecc/root_SHA1.163.crt");
    X509_Certificate link_cert = X509_Certificate("test_data/ecc/link_SHA1.166.crt");
    
    size_t fails = 0;
    Unique!X509_PublicKey pubkey = root_cert.subject_public_key();
    bool ver_ec = link_cert.check_signature(*pubkey);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct SHA1 link x509-ecdsa certificate" ) );
    return fails;
}

size_t test_sign_then_ver(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 2);
    EC_Group dom_pars = EC_Group(OID("1.3.132.0.8"));
    auto ecdsa = scoped!ECDSA_PrivateKey(rng, dom_pars);
    
    size_t fails = 0;
    PK_Signer signer = PK_Signer(ecdsa, "EMSA1(SHA-1)");
    
    auto msg = hex_decode("12345678901234567890abcdef12");
    Vector!ubyte sig = signer.sign_message(msg, rng);
    
    PK_Verifier verifier = PK_Verifier(ecdsa, "EMSA1(SHA-1)");
    
    bool ok = verifier.verify_message(msg, sig);
    
    if (!ok)
    {
        writeln("ERROR: Could not verify ECDSA signature");
        fails++;
    }
    
    sig[0]++;
    ok = verifier.verify_message(msg, sig);
    
    if (ok)
    {
        writeln("ERROR: Bogus ECDSA signature verified anyway");
        fails++;
    }
    
    return fails;
}

size_t test_ec_sign(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 3);
    size_t fails = 0;
    
    try
    {
        EC_Group dom_pars = EC_Group(OID("1.3.132.0.8"));
        auto priv_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
        string pem_encoded_key = pkcs8.PEM_encode(priv_key);
        
        PK_Signer signer = PK_Signer(priv_key, "EMSA1(SHA-224)");
        PK_Verifier verifier = PK_Verifier(priv_key, "EMSA1(SHA-224)");
        
        for(size_t i = 0; i != 256; ++i)
            signer.update(cast(ubyte)(i));
        Vector!ubyte sig = signer.signature(rng);
        
        for(uint i = 0; i != 256; ++i)
            verifier.update(cast(ubyte)(i));
        if (!verifier.check_signature(sig))
        {
            writeln("ECDSA self-test failed!");
            ++fails;
        }

        // now check valid signature, different input
        for(uint i = 1; i != 256; ++i) //starting from 1
        verifier.update(cast(ubyte)(i));

        if (verifier.check_signature(sig))
        {
            writeln("ECDSA with bad input passed validation");
            ++fails;
        }

        // now check with original in, modified signature
        sig[sig.length/2]++;
        for(uint i = 0; i != 256; ++i)
            verifier.update(cast(ubyte)(i));

        if (verifier.check_signature(sig))
        {
            writeln("ECDSA with bad signature passed validation");
            ++fails;
        }
    }
    catch (Exception e)
    {
        writeln("Exception in test_ec_sign - " ~ e.msg);
        ++fails;
    }
    return fails;
}

static if (BOTAN_HAS_RSA) 
size_t test_create_pkcs8(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;

    try
    {
        RSA_PrivateKey rsa_key = scoped!RSA_PrivateKey(rng, 1024);

        //RSA_PrivateKey rsa_key2(1024);
        //cout " ~\nequal: " ~  (rsa_key == rsa_key2));
        //DSA_PrivateKey key(DL_Group("dsa/jce/1024"));

        File rsa_priv_key = File("test_data/ecc/rsa_private.pkcs8.pem", "wb+");
        rsa_priv_key.write(pkcs8.PEM_encode(rsa_key));
        
        EC_Group dom_pars = EC_Group(OID("1.3.132.0.8"));
        auto key = scoped!ECDSA_PrivateKey(rng, dom_pars);
        
        // later used by other tests :(
        File priv_key = File("test_data/ecc/wo_dompar_private.pkcs8.pem", "wb+");
        priv_key.write( pkcs8.PEM_encode(key) );
    }
    catch (Exception e)
    {
        writeln("Exception: " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

static if (BOTAN_HAS_RSA) 
size_t test_create_and_verify(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;
    
    EC_Group dom_pars = EC_Group(OID("1.3.132.0.8"));
    auto key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    File priv_key = File("test_data/ecc/dompar_private.pkcs8.pem");
    priv_key.write( pkcs8.PEM_encode(key) );
    
    Unique!PKCS8_PrivateKey loaded_key = pkcs8.load_key("test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
    ECDSA_PrivateKey* loaded_ec_key = cast(ECDSA_PrivateKey)(*loaded_key);
    mixin( CHECK_MESSAGE( loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey" ) );
    
    Unique!PKCS8_PrivateKey loaded_key_1 = pkcs8.load_key("test_data/ecc/rsa_private.pkcs8.pem", rng);
    ECDSA_PrivateKey loaded_rsa_key = cast(ECDSA_PrivateKey)(*loaded_key_1);
    mixin( CHECK_MESSAGE( !loaded_rsa_key, "the loaded key is ECDSA_PrivateKey -> shouldn't be, is a RSA-Key" ) );
    
    //calc a curve which is not in the registry
    
    //     string p_secp = "2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809";
    string a_secp = "0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe";
    string b_secp = "0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7";
    string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
    string order_g = "0e1a16196e6000000000bc7f1618d867b15bb86474418f";
    
    //    ::Vector!ubyte sv_p_secp = hex_decode( p_secp );
    auto sv_a_secp = hex_decode( a_secp );
    auto sv_b_secp = hex_decode( b_secp );
    auto sv_G_secp_comp = hex_decode( G_secp_comp );
    auto sv_order_g = hex_decode( order_g );
    
    //    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_p_secp = BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    BigInt bi_order_g = BigInt.decode( &sv_order_g[0], sv_order_g.length );
    CurveGFp curve = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, curve );
    
    EC_Group dom_params = EC_Group(curve, p_G, bi_order_g, BigInt(1));
    if (!p_G.on_the_curve())
        throw new Internal_Error("Point not on the curve");
    
    auto key_odd_oid = scoped!ECDSA_PrivateKey(rng, dom_params);
    string key_odd_oid_str = pkcs8.PEM_encode(key_odd_oid);
    
    auto key_data_src = scoped!DataSource_Memory(key_odd_oid_str);
    Unique!PKCS8_PrivateKey loaded_key2 = pkcs8.load_key(key_data_src, rng);
    
    if (!cast(ECDSA_PrivateKey)(*loaded_key))
    {
        writeln("Failed to reload an ECDSA key with unusual parameter set");
        ++fails;
    }
    
    return fails;
}

size_t test_curve_registry(RandomNumberGenerator rng)
{
    Vector!string oids;
    oids.push_back("1.3.132.0.8");
    oids.push_back("1.2.840.10045.3.1.1");
    oids.push_back("1.2.840.10045.3.1.2");
    oids.push_back("1.2.840.10045.3.1.3");
    oids.push_back("1.2.840.10045.3.1.4");
    oids.push_back("1.2.840.10045.3.1.5");
    oids.push_back("1.2.840.10045.3.1.6");
    oids.push_back("1.2.840.10045.3.1.7");
    oids.push_back("1.3.132.0.6");
    oids.push_back("1.3.132.0.7");
    oids.push_back("1.3.132.0.28");
    oids.push_back("1.3.132.0.29");
    oids.push_back("1.3.132.0.9");
    oids.push_back("1.3.132.0.30");
    oids.push_back("1.3.132.0.31");
    oids.push_back("1.3.132.0.32");
    oids.push_back("1.3.132.0.33");
    oids.push_back("1.3.132.0.10");
    oids.push_back("1.3.132.0.34");
    oids.push_back("1.3.132.0.35");
    //oids.push_back("1.3.6.1.4.1.8301.3.1.2.9.0.38");
    oids.push_back("1.3.36.3.3.2.8.1.1.1");
    oids.push_back("1.3.36.3.3.2.8.1.1.3");
    oids.push_back("1.3.36.3.3.2.8.1.1.5");
    oids.push_back("1.3.36.3.3.2.8.1.1.7");
    oids.push_back("1.3.36.3.3.2.8.1.1.9");
    oids.push_back("1.3.36.3.3.2.8.1.1.11");
    oids.push_back("1.3.36.3.3.2.8.1.1.13");
    
    size_t fails = 0;
    
    uint i;
    foreach (oid_str; oids[])
    {
        atomicOp!"+="(total_tests, 1);
        try
        {
            OID oid = OID(oid_str);
            EC_Group dom_pars = EC_Group(oid);
            auto ecdsa = scoped!ECDSA_PrivateKey(rng, dom_pars);
            
            PK_Signer signer = PK_Signer(ecdsa, "EMSA1(SHA-1)");
            PK_Verifier verifier = PK_Verifier(ecdsa, "EMSA1(SHA-1)");
            
            auto msg = hex_decode("12345678901234567890abcdef12");
            Vector!ubyte sig = signer.sign_message(msg, rng);
            
            if (!verifier.verify_message(msg, sig))
            {
                writeln("Failed testing ECDSA sig for curve " ~ oid_str);
                ++fails;
            }
        }
        catch(Invalid_Argument e)
        {
            writeln("Error testing curve " ~ oid_str " ~ - " ~ e.msg);
            ++fails;
        }
    }
    return fails;
}

size_t test_read_pkcs8(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 2);
    auto msg = hex_decode("12345678901234567890abcdef12");
    size_t fails = 0;
    
    try
    {
        Unique!PKCS8_PrivateKey loaded_key = pkcs8.load_key("test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
        ECDSA_PrivateKey ecdsa = cast(ECDSA_PrivateKey)(*loaded_key);
        mixin( CHECK_MESSAGE( ecdsa, "the loaded key could not be converted into an ECDSA_PrivateKey" ) );
        
        PK_Signer signer = PK_Signer(ecdsa, "EMSA1(SHA-1)");
        
        Vector!ubyte sig = signer.sign_message(msg, rng);
        
        PK_Verifier verifier = PK_Verifier(ecdsa, "EMSA1(SHA-1)");
        
        mixin( CHECK_MESSAGE(verifier.verify_message(msg, sig), "generated sig could not be verified positively"));
    }
    catch (Exception e)
    {
        ++fails;
        writeln("Exception in test_read_pkcs8 - " ~ e.msg);
    }
    
    try
    {
        Unique!PKCS8_PrivateKey loaded_key_nodp = pkcs8.load_key("test_data/ecc/nodompar_private.pkcs8.pem", rng);
        // anew in each test with unregistered domain-parameters
        ECDSA_PrivateKey ecdsa_nodp = cast(ECDSA_PrivateKey)(*loaded_key_nodp);
        mixin( CHECK_MESSAGE( ecdsa_nodp, "the loaded key could not be converted into an ECDSA_PrivateKey" ) );
        
        PK_Signer signer = PK_Signer(ecdsa_nodp, "EMSA1(SHA-1)");
        PK_Verifier verifier = PK_Verifier(ecdsa_nodp, "EMSA1(SHA-1)");
        
        Vector!ubyte signature_nodp = signer.sign_message(msg, rng);
        
        mixin( CHECK_MESSAGE(verifier.verify_message(msg, signature_nodp),
                             "generated signature could not be verified positively (no_dom)"));
        
        try
        {
            Unique!PKCS8_PrivateKey loaded_key_withdp = pkcs8.load_key("test_data/ecc/withdompar_private.pkcs8.pem", rng);
            
            writeln("Unexpected success: loaded key with unknown OID");
            ++fails;
        }
        catch (Exception) { /* OK */ }
    }
    catch (Exception e)
    {
        writeln("Exception in test_read_pkcs8 - " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

size_t test_ecc_key_with_rfc5915_extensions(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;
    
    try
    {
        Unique!PKCS8_PrivateKey pkcs8 = pkcs8.load_key("test_data/ecc/ecc_private_with_rfc5915_ext.pem", rng);
        
        if (!cast(ECDSA_PrivateKey)(*pkcs8))
        {
            writeln("Loaded RFC 5915 key, but got something other than an ECDSA key");
            ++fails;
        }
    }
    catch(Exception e)
    {
        writeln("Exception in " ~ __func__ " ~ - " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

size_t test_pk_keygen(RandomNumberGenerator rng) {
    size_t fails = 0;

    string[] ecdsa_list = ["secp112r1", "secp128r1", "secp160r1", "secp192r1",
        "secp224r1", "secp256r1", "secp384r1", "secp521r1"];
    
    foreach (ecdsa; ecdsa_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!ECDSA_PrivateKey(rng, EC_Group(OIDS.lookup(ecdsa)));
        key.check_key(rng, true);
        fails += validate_save_and_load(&key, rng);
    }

    return fails;
}


size_t ecdsa_sig_kat(string group_id,
                     string x,
                     string hash,
                     string msg,
                     string nonce,
                     string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    EC_Group group = EC_Group(OIDS.lookup(group_id));
    auto ecdsa = scoped!ECDSA_PrivateKey(rng, group, BigInt(x));
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PK_Verifier verify = PK_Verifier(ecdsa, padding);
    PK_Signer sign = PK_Signer(ecdsa, padding);
    
    return validate_signature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}

unittest
{
    size_t fails = 0;
    
    AutoSeeded_RNG rng;
    
    fails += test_hash_larger_than_n(rng);
    static if (BOTAN_HAS_X509_CERTIFICATES) {
        fails += test_decode_ecdsa_X509();
        fails += test_decode_ver_link_SHA256();
        fails += test_decode_ver_link_SHA1();
    }
    fails += test_sign_then_ver(rng);
    fails += test_ec_sign(rng);

    static if (BOTAN_HAS_RSA) {
        fails += test_create_pkcs8(rng);
        fails += test_create_and_verify(rng);
    }

    fails += test_curve_registry(rng);
    fails += test_read_pkcs8(rng);
    fails += test_ecc_key_with_rfc5915_extensions(rng);
    fails += test_pk_keygen(rng);



    File ecdsa_sig = File("test_data/pubkey/ecdsa.vec", "r");

    fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", true,
                              (string[string] m) {
                                return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
                            });


    test_report("ECDSA", total_tests, fails);

}
