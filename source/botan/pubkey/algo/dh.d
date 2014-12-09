/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dh;

import botan.constants;
static if (BOTAN_HAS_DIFFIE_HELLMAN):

public import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;

/**
* This class represents Diffie-Hellman public keys.
*/
class DHPublicKey
{
public:
    __gshared immutable string algoName = "DH";

    /*
    * Return the public value for key agreement
    */
    Vector!ubyte publicValue() const
    {
        return unlock(BigInt.encode1363(m_pub.m_y, m_pub.groupP().bytes()));
    }

    size_t maxInputBits() const { return groupP().bits(); }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        m_pub = new DLSchemePublicKey(alg_id, key_bits, DLGroup.ANSI_X9_42, algoName, 0, null, &maxInputBits);
    }

    /**
    * Construct a public key with the specified parameters.
    * @param grp = the DL group to use in the key
    * @param y = the public value y
    */
    this(in DLGroup grp, in BigInt y1)
    {
		m_pub = new DLSchemePublicKey(grp, y1, DLGroup.ANSI_X9_42, algoName, 0, null, &maxInputBits);
    }

	this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
	this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

	alias m_pub this;
private:
	DLSchemePublicKey m_pub;
}

/**
* This class represents Diffie-Hellman private keys.
*/
class DHPrivateKey : DHPublicKey, PKKeyAgreementKey
{
public:
    /*
    * Return the public value for key agreement
    */
	override Vector!ubyte publicValue() const
    {
        return super.publicValue();
    }

    /**
    * Load a DH private key
    * @param alg_id = the algorithm id
    * @param key_bits = the subject public key
    * @param rng = a random number generator
    */
    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        m_priv = DLSchemePrivateKey(alg_id, key_bits, DLGroup.ANSI_X9_42, algoName, 0, null, &maxInputBits);
        if (m_priv.m_y == 0)
            m_priv.m_y = powerMod(m_priv.groupG(), m_priv.m_x, m_priv.groupP());
        
        m_priv.loadCheck(rng);
    }

    /**
    * Construct a private key with predetermined value.
    * @param rng = random number generator to use
    * @param grp = the group to be used in the key
    * @param x_args = the key's secret value (or if zero, generate a new key)
    */
    this(RandomNumberGenerator rng, DLGroup grp, BigInt x_arg = 0)
    {
        
        if (x_arg == 0)
        {
            const BigInt p = grp.getP();
            x_arg.randomize(rng, 2 * dlWorkFactor(p.bits()));
        }

        BigInt y1 = powerMod(grp.getG(), x_arg, grp.getP());
        
		m_priv = new DLSchemePrivateKey(grp, y1, x_arg, DLGroup.ANSI_X9_42, algoName, null, &maxInputBits);

        if (x_arg == 0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);
    }

	this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; }

	alias m_priv this;
private:
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
        m_p = dh.groupP();
        m_powermod_x_p = FixedExponentPowerMod(dh.getX(), m_p);
        BigInt k = BigInt(rng, m_p.bits() - 1);
        m_blinder = Blinder(k, m_powermod_x_p(inverseMod(k, m_p)), m_p);
    }

	override SecureVector!ubyte agree(in ubyte* w, size_t w_len)
    {
        BigInt input = BigInt.decode(w, w_len);
        
        if (input <= 1 || input >= m_p - 1)
            throw new InvalidArgument("DH agreement - invalid key provided");
        
        BigInt r = m_blinder.unblind(m_powermod_x_p(m_blinder.blind(input)));
        
        return BigInt.encode1363(r, m_p.bytes());
    }

private:
    const BigInt m_p;

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
import core.atomic;

private __gshared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;

    string[] dh_list = ["modp/ietf/1024", "modp/ietf/2048", "modp/ietf/4096", "dsa/jce/1024"];

    foreach (dh; dh_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!DHPrivateKey(rng, ECGroup(OIDS.lookup(dh)));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(&key, rng);
    }
    
    return fails;
}

size_t dhSigKat(string p, string g, string x, string y, string kdf, string outlen, string key)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    BigInt p_bn = BigInt(p);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    BigInt y_bn = BigInt(y);
    
    DLGroup domain = DLGroup(p_bn, g_bn);
    
    auto mykey = scoped!DHPrivateKey(rng, domain, x_bn);
    auto otherkey = scoped!DHPublicKey(domain, y_bn);
    
    if (kdf == "")
        kdf = "Raw";
    
    size_t keylen = 0;
    if (outlen != "")
        keylen = to!uint(outlen);
    
    auto kas = scoped!PKKeyAgreement(mykey, kdf);
    
    return validateKas(kas, "DH/" ~ kdf, otherkey.publicValue(), key, keylen);
}

unittest
{
    size_t fails = 0;

    AutoSeededRNG rng;

    fails += testPkKeygen(rng);

    File dh_sig = File("test_data/pubkey/dh.vec", "r");
    
    fails += runTestsBb(dh_sig, "DH Kex", "K", true,
                          (string[string] m) {
                                return dhSigKat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
                            });


    testReport("DH", total_tests, fails);

}