/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dh;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_DIFFIE_HELLMAN):

public import botan.pubkey.algo.dl_algo;
public import botan.pubkey.pubkey;
public import botan.math.ec_gfp.ec_group;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;
import memutils.helpers : Embed;

struct DHOptions {
	enum algoName = "DH";
	enum format = DLGroup.ANSI_X9_42;
}

/**
* This class represents Diffie-Hellman public keys.
*/
struct DHPublicKey
{
public:
	alias Options = DHOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_pub = new DLSchemePublicKey(Options(), alg_id, key_bits);
    }

    /**
    * Construct a public key with the specified parameters.
    * @param grp = the DL group to use in the key
    * @param y = the public value y
    */
    this()(auto const ref DLGroup grp, auto const ref BigInt y1)
    {
		m_pub = new DLSchemePublicKey(Options(), grp, y1);
    }

    this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
    this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

	mixin Embed!m_pub;

    DLSchemePublicKey m_pub;
}

/**
* This class represents Diffie-Hellman private keys.
*/
struct DHPrivateKey
{
public:
	alias Options = DHOptions;
	__gshared immutable string algoName = Options.algoName;

    /**
    * Load a DH private key
    * @param alg_id = the algorithm id
    * @param key_bits = the subject public key
    * @param rng = a random number generator
    */
    this()(in AlgorithmIdentifier alg_id,
           auto const ref SecureVector!ubyte key_bits,
           RandomNumberGenerator rng) 
    {

		m_priv = new DLSchemePrivateKey(Options(), alg_id, key_bits);
        if (m_priv.getY() == 0)
            m_priv.setY(powerMod(m_priv.groupG(), m_priv.getX(), m_priv.groupP()));
        m_priv.loadCheck(rng);
    }

    /**
    * Construct a private key with predetermined value.
    * @param rng = random number generator to use
    * @param grp = the group to be used in the key
    * @param x_args = the key's secret value (or if zero, generate a new key)
    */
    this()(RandomNumberGenerator rng, auto const ref DLGroup grp, BigInt x_args = 0)
    {
        
		const BigInt* p = &grp.getP();

		if (x_args == 0)
			x_args.randomize(rng, 2 * dlWorkFactor(p.bits()));

		BigInt y1 = powerMod(grp.getG(), x_args, *p);
        
		m_priv = new DLSchemePrivateKey(Options(), grp, y1, x_args);

		if (x_args == 0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);
    }

	this()(RandomNumberGenerator rng, auto const ref DLGroup grp) { auto bi = BigInt(0); this(rng, grp, bi.move()); }
    this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; }

	mixin Embed!m_priv;

    DLSchemePrivateKey m_priv;


}

/**
* DH operation
*/
class DHKAOperation : KeyAgreement
{
public:
    this(in PrivateKey pkey, RandomNumberGenerator rng) {
        this(cast(DLSchemePrivateKey) pkey, rng);
    }

    this(in DHPrivateKey pkey, RandomNumberGenerator rng) {
        this(pkey.m_priv, rng);
    }

    this(in DLSchemePrivateKey dh, RandomNumberGenerator rng) 
    {
        assert(dh.algoName == DHPublicKey.algoName);
        m_p = &dh.groupP();
        m_powermod_x_p = FixedExponentPowerMod(dh.getX(), *m_p);
        BigInt k = BigInt(rng, m_p.bits() - 1);
		auto d = (*m_powermod_x_p)(inverseMod(k, *m_p));
        m_blinder = Blinder(k, d, *m_p);
    }

    override SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
    {
        BigInt input = BigInt.decode(w, w_len);
        
        if (input <= 1 || input >= *m_p - 1)
            throw new InvalidArgument("DH agreement - invalid key provided");
        
        const BigInt r = m_blinder.unblind((*m_powermod_x_p)(m_blinder.blind(input)));
        
        return BigInt.encode1363(r, m_p.bytes());
    }

private:
    const BigInt* m_p;

    FixedExponentPowerMod m_powermod_x_p;
    Blinder m_blinder;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.pubkey.algo.dh;
import botan.codec.hex;
import botan.asn1.oids;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;

    string[] dh_list = ["modp/ietf/1024", "modp/ietf/2048", "modp/ietf/4096", "dsa/jce/1024"];

    foreach (dh; dh_list) {
        atomicOp!"+="(total_tests, 1);
        DHPrivateKey key = DHPrivateKey(rng, DLGroup(dh));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
    }
    
    return fails;
}

size_t dhSigKat(string p, string g, string x, string y, string kdf, string outlen, string key)
{
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    BigInt p_bn = BigInt(p);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    BigInt y_bn = BigInt(y);
    
    DLGroup domain = DLGroup(p_bn, g_bn);
    
    auto mykey = DHPrivateKey(rng, domain, x_bn.move());
    auto otherkey = DHPublicKey(domain, y_bn.move());
    
    if (kdf == "")
        kdf = "Raw";
    
    size_t keylen = 0;
    if (outlen != "")
        keylen = to!uint(outlen);
    
    auto kas = scoped!PKKeyAgreement(mykey, kdf);
    
    return validateKas(kas, "DH/" ~ kdf, otherkey.publicValue(), key, keylen);
}

static if (!SKIP_DH_TEST) unittest
{
    logDebug("Testing dh.d ...");
    size_t fails = 0;

    auto rng = AutoSeededRNG();

    fails += testPkKeygen(rng);

    File dh_sig = File("../test_data/pubkey/dh.vec", "r");
    
    fails += runTestsBb(dh_sig, "DH Kex", "K", true,
                          (ref HashMap!(string, string) m) {
                                return dhSigKat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
                            });


    testReport("DH", total_tests, fails);

}