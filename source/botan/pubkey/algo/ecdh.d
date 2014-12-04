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
static if (BOTAN_HAS_ECDH):

import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.math.bigint.bigint;

/**
* This class represents ECDH Public Keys.
*/
class ECDHPublicKey : ECPublicKey
{
public:

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits) 
    { 
        super(alg_id, key_bits);
    }

    /**
    * Construct a public key from a given public point.
    * @param dom_par = the domain parameters associated with this key
    * @param public_point = the public point defining this key
    */
    this(in ECGroup dom_par, in PointGFp public_point) 
    {
        super(dom_par, public_point);
    }

    /**
    * Get this keys algorithm name.
    * @return this keys algorithm name
    */
    @property string algoName() const { return "ECDH"; }

    /**
    * Get the maximum number of bits allowed to be fed to this key.
    * This is the bitlength of the order of the base point.

    * @return maximum number of input bits
    */
    size_t maxInputBits() const { return domain().getOrder().bits(); }

    /**
    * @return public point value
    */
    Vector!ubyte publicValue() const
    { return unlock(EC2OSP(public_point(), PointGFp.UNCOMPRESSED)); }

protected:
    this() {}
}

/**
* This class represents ECDH Private Keys.
*/
final class ECDHPrivateKey : ECDHPublicKey,
                              ECPrivateKey,
                              PKKeyAgreementKey
{
public:

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits) 
    {
        super(alg_id, key_bits);
    }

    /**
    * Generate a new private key
    * @param rng = a random number generator
    * @param domain = parameters to used for this key
    * @param x = the private key; if zero, a new random key is generated
    */
    this(RandomNumberGenerator rng, in ECGroup domain,
        in BigInt x = 0) 
    {
        super(rng, domain, x);
    }

    Vector!ubyte publicValue() const
    { return super.publicValue(); }
}

/**
* ECDH operation
*/
final class ECDHKAOperation : KeyAgreement
{
public:
    this(in ECDHPrivateKey key) 
    {
        m_curve = key.domain().getCurve();
        m_cofactor = key.domain().getCofactor();
        l_times_priv = inverseMod(m_cofactor, key.domain().getOrder()) * key.privateValue();
    }

    SecureVector!ubyte agree(in ubyte* w, size_t w_len)
    {
        PointGFp point = OS2ECP(w, w_len, m_curve);
        
        PointGFp S = (m_cofactor * point) * m_l_times_priv;

        assert(S.onTheCurve(), "ECDH agreed value was on the curve");
        
        return BigInt.encode1363(S.getAffineX(),
                                  m_curve.getP().bytes());
    }
private:
    const CurveGFp m_curve;
    const BigInt m_cofactor;
    BigInt m_l_times_priv;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.pubkey;
import botan.cert.x509.x509self;
import botan.asn1.der_enc;

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
        writeln("The two keys didn't match!");
        writeln("Alice's key was: " ~ alice_key.asString());
        writeln("Bob's key was: " ~ bob_key.asString());
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
    foreach (oid_str; oids)
    {
        OID oid = OID(oids_str);
        ECGroup dom_pars = ECGroup(oid);
        
        ECDHPrivateKey private_a = scoped!ECDHPrivateKey(rng, dom_pars);
        ECDHPrivateKey private_b = scoped!ECDHPrivateKey(rng, dom_pars);
        
        PKKeyAgreement ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
        PKKeyAgreement kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
        
        SymmetricKey alice_key = ka.deriveKey(32, private_b.publicValue());
        SymmetricKey bob_key = kb.deriveKey(32, private_a.publicValue());
        
        mixin( CHECK_MESSAGE( alice_key == bob_key, "different keys - " ~ "Alice's key was: " ~ alice_key.asString() ~ ", Bob's key was: " ~ bob_key.asString() ) );
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
    foreach (oid_str; oids)
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
        
        mixin( CHECK_MESSAGE( alice_key == bob_key, "different keys - " ~ "Alice's key was: " ~ alice_key.asString() ~ ", Bob's key was: " ~ bob_key.asString() ) );
        
    }
    
    return fails;
}

unittest
{
    size_t fails = 0;
    
    AutoSeededRNG rng;
    
    fails += test_ecdh_normal_derivation(rng);
    fails += test_ecdh_some_dp(rng);
    fails += test_ecdh_der_derivation(rng);
    
    testReport("ECDH", 7, fails);
}