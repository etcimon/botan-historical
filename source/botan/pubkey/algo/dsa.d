/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dsa;

import botan.constants;
static if (BOTAN_HAS_DSA):

public import botan.pubkey.algo.dl_algo;
public import botan.pubkey.pubkey;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;

/**
* DSA Public Key
*/
class DSAPublicKey
{
public:
    __gshared immutable string algoName = "DSA";
    size_t messagePartSize() const { return m_pub.groupQ().bytes(); }
    size_t maxInputBits() const { return m_pub.groupQ().bits(); }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits) 
    {
        m_pub = new DLSchemePublicKey(alg_id, key_bits, DLGroup.ANSI_X9_57, algoName, 2, null, &maxInputBits, &messagePartSize);
    }

    /*
    * DSAPublicKey Constructor
    */
    this(in DLGroup grp, in BigInt y1)
    {
        m_pub = new DLSchemePublicKey(grp, y1, DLGroup.ANSI_X9_57, algoName, 2, null, &maxInputBits, &messagePartSize);
    }

    this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
    this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

    alias m_pub this;
private:
    DLSchemePublicKey m_pub;
}

/**
* DSA Private Key
*/
final class DSAPrivateKey : DSAPublicKey, PrivateKey
{
public:
    /*
    * Create a DSA private key
    */
    this(RandomNumberGenerator rng, DLGroup dl_group, BigInt x_arg = 0)
    {
        
        if (x_arg == 0)
            x_arg = BigInt.randomInteger(rng, 2, dl_group.getQ() - 1);
        
        BigInt y1 = powerMod(dl_group.getG(), x_arg, dl_group.getP());
        
        m_priv = new DLSchemePrivateKey(dl_group, y1, x_arg, DLGroup.ANSI_X9_57, algoName, 2, &checkKey, &maxInputBits, &messagePartSize);

        if (x_arg == 0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);
    }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        m_priv = new DLSchemePublicKey(alg_id, key_bits, DLGroup.ANSI_X9_57, algoName, 2, &checkKey, &maxInputBits, &messagePartSize);
        m_priv.m_y = powerMod(m_priv.groupG(), m_priv.m_x, m_priv.groupP());
        
        m_priv.loadCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; }

    /*
    * Check Private DSA Parameters
    */
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!m_priv.checkKey(rng, strong, true) || m_priv.m_x >= m_priv.groupQ())
            return false;
        
        if (!strong)
            return true;
        
        return signatureConsistencyCheck(rng, m_priv, "EMSA1(SHA-1)");
    }

    alias m_priv this;
private:
    DLSchemePrivateKey m_priv;
}

/**
* Object that can create a DSA signature
*/
final class DSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) {
        this(cast(DLSchemePrivateKey) pkey);
    }

    this(in DSAPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in DLSchemePrivateKey dsa)
    { 
        assert(nr.algoName == DSAPublicKey.algoName);
        m_q = dsa.groupQ();
        m_x = dsa.getX();
        m_powermod_g_p = FixedBasePowerMod(dsa.groupG(), dsa.groupP());
        m_mod_q = dsa.groupQ();
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override SecureVector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        import std.concurrency : spawn, receiveOnly, thisTid, send;
        rng.addEntropy(msg, msg_len);
        
        BigInt i = BigInt(msg, msg_len);
        BigInt r = 0, s = 0;
        
        while (r == 0 || s == 0)
        {
            BigInt k;
            do
                k.randomize(rng, m_q.bits());
            while (k >= m_q);
            
            auto tid = spawn((Tid tid, FixedBasePowerMod powermod_g_p2, BigInt k2){ send(tid, m_mod_q.reduce(powermod_g_p2(k2))); }, thisTid, m_powermod_g_p, k);
            
            s = inverseMod(k, m_q);

            r = receiveOnly!BigInt();

            s = m_mod_q.multiply(s, mulAdd(m_x, r, i));
        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_q.bytes());
        r.binaryEncode(&output[output.length / 2 - r.bytes()]);
        s.binaryEncode(&output[output.length - s.bytes()]);
        return output;
    }
private:
    const BigInt m_q;
    const BigInt m_x;
    FixedBasePowerMod m_powermod_g_p;
    ModularReducer m_mod_q;
}

/**
* Object that can verify a DSA signature
*/
final class DSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(DLSchemePublicKey) pkey);
    }

    this(in DSAPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in DLSchemePublicKey dsa) 
    {
        assert(dsa.algoName == DSAPublicKey.algoName);
        m_q = dsa.groupQ();
        m_y = dsa.getY();
        m_powermod_g_p = FixedBasePowerMod(dsa.groupG(), dsa.groupP());
        m_powermod_y_p = FixedBasePowerMod(y, dsa.groupP());
        m_mod_p = ModularReducer(dsa.groupP());
        m_mod_q = ModularReducer(dsa.groupQ());
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override bool withRecovery() const { return false; }

    override bool verify(in ubyte* msg, size_t msg_len,
                in ubyte* sig, size_t sig_len)
    {
        import std.concurrency : spawn, receiveOnly, send, thisTid;
        const BigInt q = mod_q.getModulus();
        
        if (sig_len != 2*q.bytes() || msg_len > q.bytes())
            return false;
        
        BigInt r = BigInt(sig, q.bytes());
        BigInt s = BigInt(sig + q.bytes(), q.bytes());
        BigInt i = BigInt(msg, msg_len);
        
        if (r <= 0 || r >= q || s <= 0 || s >= q)
            return false;
        
        s = inverseMod(s, q);
        
        auto tid = spawn((Tid tid, FixedBasePowerMod powermod_g_p2, BigInt mod_q2, BigInt s2, BigInt i2) 
                         { send(tid, powermod_g_p2(mod_q2.multiply(s2, i2))); }, 
                            thisTid, m_powermod_g_p, m_mod_q, s, i);
        
        BigInt s_r = m_powermod_y_p(m_mod_q.multiply(s, r));
        BigInt s_i = receiveOnly!BigInt();
        
        s = m_mod_p.multiply(s_i, s_r);
        
        return (m_mod_q.reduce(s) == r);
    }

private:
    const BigInt m_q;
    const BigInt m_y;

    FixedBasePowerMod m_powermod_g_p, m_powermod_y_p;
    ModularReducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;

import core.atomic;
private __gshared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng) {
    size_t fails;
    string[] dsa_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    foreach (dsa; dsa_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!DSAPrivateKey(rng, DLGroup(dsa));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(&key, rng);
    }
    
    return fails;
}

size_t dsaSigKat(string p,
                   string q,
                   string g,
                   string x,
                   string hash,
                   string msg,
                   string nonce,
                   string signature)
{
    atomicOp!"+="(total_tests, 1);
    
    AutoSeededRNG rng;
    
    BigInt p_bn = BigInt(p);
    BigInt q_bn = BigInt(q);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, q_bn, g_bn);
    auto privkey = scoped!DSAPrivateKey(rng, group, x_bn);
    
    auto pubkey = scoped!DSAPublicKey(privkey);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}

unittest
{
    size_t fails;
    
    AutoSeededRNG rng;
    
    fails += testPkKeygen(rng);
    
    File dsa_sig = File("test_data/pubkey/dsa.vec", "r");
    
    fails += runTestsBb(dsa_sig, "DSA Signature", "Signature", true,
                          (string[string] m)
                          {
        return dsaSigKat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
    });
    
    testReport("dsa", total_tests, fails);
}

