/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dh;

import botan.constants;
static if (BOTAN_HAS_DIFFIE_HELLMAN):

import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;

/**
* This class represents Diffie-Hellman public keys.
*/
class DHPublicKey : DL_SchemePublicKey
{
public:
    @property string algoName() const { return "DH"; }

    /*
    * Return the public value for key agreement
    */
    Vector!ubyte publicValue() const
    {
        return unlock(BigInt.encode1363(y, group_p().bytes()));
    }

    size_t maxInputBits() const { return group_p().bits(); }

    DLGroup.Format groupFormat() const { return DLGroup.ANSI_X9_42; }

    this(in AlgorithmIdentifier alg_id,
                     in SecureVector!ubyte key_bits)
    {
        super(alg_id, key_bits, DLGroup.ANSI_X9_42);
    }

    /**
    * Construct a public key with the specified parameters.
    * @param grp = the DL group to use in the key
    * @param y = the public value y
    */
    this(in DLGroup grp, in BigInt y1)
    {
        m_group = grp;
        m_y = y1;
    }
protected:
    this() {}
}

/**
* This class represents Diffie-Hellman private keys.
*/
class DHPrivateKey : DHPublicKey,
                      PKKeyAgreementKey,
                      DL_SchemePrivateKey
{
public:
    /*
    * Return the public value for key agreement
    */
    Vector!ubyte publicValue() const
    {
        return publicValue();
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
        super(alg_id, key_bits, DLGroup.ANSI_X9_42);
        if (m_y == 0)
            m_y = powerMod(group_g(), m_x, group_p());
        
        load_check(rng);
    }

    /**
    * Construct a private key with predetermined value.
    * @param rng = random number generator to use
    * @param grp = the group to be used in the key
    * @param x_args = the key's secret value (or if zero, generate a new key)
    */
    this(RandomNumberGenerator rng,
         in DLGroup grp,
         in BigInt x_arg = 0)
    {
        m_group = grp;
        m_x = x_arg;
        
        if (m_x == 0)
        {
            const BigInt m_p = group_p();
            m_x.randomize(rng, 2 * dl_work_factor(m_p.bits()));
        }
        
        if (m_y == 0)
            m_y = powerMod(group_g(), m_x, group_p());
        
        if (m_x == 0)
            gen_check(rng);
        else
            load_check(rng);
    }
}

/**
* DH operation
*/
class DHKAOperation : Key_Agreement
{
public:
    this(in DHPrivateKey dh, RandomNumberGenerator rng) 
    {
        m_p = dh.groupP();
        m_powermod_x_p = Fixed_Exponent_Power_Mod(dh.getX(), m_p);
        BigInt k = BigInt(rng, m_p.bits() - 1);
        m_blinder = Blinder(k, m_powermod_x_p(inverseMod(k, m_p)), m_p);
    }

    SecureVector!ubyte agree(in ubyte* w, size_t w_len)
    {
        BigInt input = BigInt.decode(w, w_len);
        
        if (input <= 1 || input >= m_p - 1)
            throw new InvalidArgument("DH agreement - invalid key provided");
        
        BigInt r = m_blinder.unblind(m_powermod_x_p(m_blinder.blind(input)));
        
        return BigInt.encode1363(r, m_p.bytes());
    }

private:
    const BigInt m_p;

    Fixed_Exponent_Power_Mod m_powermod_x_p;
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
        fails += validate_save_and_load(&key, rng);
    }
    
    return fails;
}

size_t dhSigKat(string p, string g, string x, string y, string kdf, string outlen, string key)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
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
    
    return validate_kas(kas, "DH/" ~ kdf, otherkey.publicValue(), key, keylen);
}

unittest
{
    size_t fails = 0;

    AutoSeeded_RNG rng;

    fails += testPkKeygen(rng);

    File dh_sig = File("test_data/pubkey/dh.vec", "r");
    
    fails += runTestsBb(dh_sig, "DH Kex", "K", true,
                          (string[string] m) {
                                return dhSigKat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
                            });


    testReport("DH", total_tests, fails);

}