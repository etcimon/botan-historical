/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*             Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecdh;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECDH):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.math.bigint.bigint;

/**
* This class represents ECDH Public Keys.
*/
class ECDHPublicKey
{
public:
    __gshared immutable string algoName = "ECDH";

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    { 
        m_pub = new ECPublicKey(alg_id, key_bits, algoName, false);
    }

    /**
    * Construct a public key from a given public point.
    * @param dom_par = the domain parameters associated with this key
    * @param public_point = the public point defining this key
    */
    this(const ref ECGroup dom_par, const ref PointGFp public_point) 
    {
        m_pub = new ECPublicKey(dom_par, public_point, algoName, false);
    }

    this(PrivateKey pkey) { m_pub = cast(ECPublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    alias m_pub this;

    ECPublicKey m_pub;
}

/**
* This class represents ECDH Private Keys.
*/
final class ECDHPrivateKey : ECDHPublicKey
{
public:
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        m_priv = new ECPrivateKey(alg_id, key_bits, algoName, false);
        super(m_priv);
    }

    /**
    * Generate a new private key
    * @param rng = a random number generator
    * @param domain = parameters to used for this key
    * @param x = the private key; if zero, a new random key is generated
    */
	this(RandomNumberGenerator rng, const ref ECGroup domain, BigInt x = BigInt(0)) 
    {
        m_priv = new ECPrivateKey(rng, domain, x, algoName, false);
        super(m_priv);
    }

	this(RandomNumberGenerator rng, const ref ECGroup domain) { auto bi = BigInt(0); this(rng, domain, bi.move()); }

    this(PrivateKey pkey) { m_priv = cast(ECPrivateKey) pkey; super(m_priv); }

    alias m_priv this;

    ECPrivateKey m_priv;

}

/**
* ECDH operation
*/
final class ECDHKAOperation : KeyAgreement
{
public:
    this(in PrivateKey pkey) {
        this(cast(ECPrivateKey) pkey);
    }

    this(in ECDHPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in ECPrivateKey key) 
    {
        m_curve = key.domain().getCurve().dup;
        m_cofactor = &key.domain().getCofactor();
        m_l_times_priv = inverseMod(*m_cofactor, key.domain().getOrder()) * key.privateValue();
    }

    override SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
    {
        PointGFp point = OS2ECP(w, w_len, m_curve);
        
        PointGFp S = (point * (*m_cofactor)) * m_l_times_priv;

        assert(S.onTheCurve(), "ECDH agreed value was on the curve");
        
        return BigInt.encode1363(S.getAffineX(),
                                  m_curve.getP().bytes());
    }
private:
    CurveGFp m_curve;
    const BigInt* m_cofactor;
    BigInt m_l_times_priv;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.pubkey;
import botan.cert.x509.x509self;
import botan.asn1.der_enc;
import botan.rng.auto_rng;
import core.atomic : atomicOp;
shared(size_t) total_tests;

size_t testEcdhNormalDerivation(RandomNumberGenerator rng)
{
    size_t fails = 0;
    
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    
    ECDHPrivateKey private_a = scoped!ECDHPrivateKey(rng, dom_pars);
    
    ECDHPrivateKey private_b = scoped!ECDHPrivateKey(rng, dom_pars); //public_a.getCurve()
    
    PKKeyAgreement ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
    PKKeyAgreement kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
    
    SymmetricKey alice_key = ka.deriveKey(32, private_b.publicValue());
    SymmetricKey bob_key = kb.deriveKey(32, private_a.publicValue());
    // 1 test
    if (alice_key != bob_key)
    {
        logTrace("The two keys didn't match!");
        logTrace("Alice's key was: " ~ alice_key.toString());
        logTrace("Bob's key was: " ~ bob_key.toString());
        atomicOp!"+="(total_tests, cast(size_t)1);
        ++fails;
    }
    
    return fails;
}

size_t testEcdhSomeDp(RandomNumberGenerator rng)
{
    size_t fails = 0;
    
    Vector!string oids;
    oids.pushBack("1.2.840.10045.3.1.7");
    oids.pushBack("1.3.132.0.8");
    oids.pushBack("1.2.840.10045.3.1.1");
    // 3 tests
    foreach (oid_str; oids[])
    {
        OID oid = OID(oid_str);
        ECGroup dom_pars = ECGroup(oid);
        
        ECDHPrivateKey private_a = scoped!ECDHPrivateKey(rng, dom_pars);
        ECDHPrivateKey private_b = scoped!ECDHPrivateKey(rng, dom_pars);
        
        PKKeyAgreement ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
        PKKeyAgreement kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
        
        SymmetricKey alice_key = ka.deriveKey(32, private_b.publicValue());
        SymmetricKey bob_key = kb.deriveKey(32, private_a.publicValue());
        
        mixin( CHECK_MESSAGE( `alice_key == bob_key`, "different keys - Alice s key was: ` ~ alice_key.toString() ~ `, Bob's key was: ` ~ bob_key.toString() ~ `" ) );
    }
    
    return fails;
}

size_t testEcdhDerDerivation(RandomNumberGenerator rng)
{
    size_t fails = 0;
    
    Vector!string oids;
    oids.pushBack("1.2.840.10045.3.1.7");
    oids.pushBack("1.3.132.0.8");
    oids.pushBack("1.2.840.10045.3.1.1");
    // 3 tests
    foreach (oid_str; oids[])
    {
        OID oid = OID(oid_str);
        ECGroup dom_pars = ECGroup(oid);
        
        auto private_a = scoped!ECDHPrivateKey(rng, dom_pars);
        auto private_b = scoped!ECDHPrivateKey(rng, dom_pars);
        
        Vector!ubyte key_a = private_a.publicValue();
        Vector!ubyte key_b = private_b.publicValue();
        
        PKKeyAgreement ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
        PKKeyAgreement kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
        
        SymmetricKey alice_key = ka.deriveKey(32, key_b);
        SymmetricKey bob_key = kb.deriveKey(32, key_a);
        
        mixin( CHECK_MESSAGE( `alice_key == bob_key`, "different keys - Alice's key was: ` ~ alice_key.toString() ~ `, Bob's key was: ` ~ bob_key.toString() ~ `" ) );
        
    }
    
    return fails;
}

static if (!SKIP_ECDH_TEST) unittest
{
    logDebug("Testing ecdh.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    fails += testEcdhNormalDerivation(rng);
    fails += testEcdhSomeDp(rng);
    fails += testEcdhDerDerivation(rng);
    
    testReport("ECDH", total_tests, fails);
}