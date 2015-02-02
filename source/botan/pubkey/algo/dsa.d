/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_DSA):

public import botan.pubkey.algo.dl_algo;
public import botan.pubkey.pubkey;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import std.concurrency;

/**
* DSA Public Key
*/
class DSAPublicKey
{
public:
    __gshared immutable string algoName = "DSA";
    size_t messagePartSize() const { return m_pub.groupQ().bytes(); }
    size_t maxInputBits() const { return m_pub.groupQ().bits(); }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        m_pub = new DLSchemePublicKey(alg_id, key_bits, DLGroup.ANSI_X9_57, algoName, 2, null, &maxInputBits, &messagePartSize);
    }

    /*
    * DSAPublicKey Constructor
    */
    this(DLGroup grp, BigInt y1)
    {
        m_pub = new DLSchemePublicKey(grp, y1, DLGroup.ANSI_X9_57, algoName, 2, null, &maxInputBits, &messagePartSize);
    }

    this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
    this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

    alias m_pub this;

    DLSchemePublicKey m_pub;
}

/**
* DSA Private Key
*/
final class DSAPrivateKey : DSAPublicKey
{
public:
    /*
    * Create a DSA private key
    */
    this(RandomNumberGenerator rng, DLGroup dl_group, BigInt x_arg = 0)
    {
        
        if (x_arg == 0) {
			auto bi = BigInt(2);
            x_arg = BigInt.randomInteger(rng, bi, dl_group.getQ() - 1);
		}
        BigInt y1 = powerMod(dl_group.getG(), x_arg, dl_group.getP());
        
        m_priv = new DLSchemePrivateKey(dl_group, y1, x_arg, DLGroup.ANSI_X9_57, algoName, 2, &checkKey, &maxInputBits, &messagePartSize);

        if (x_arg == 0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);

        super(dl_group.move(), y1.move());
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        m_priv = new DLSchemePrivateKey(alg_id, key_bits, DLGroup.ANSI_X9_57, algoName, 2, &checkKey, &maxInputBits, &messagePartSize);
        super(m_priv);
        m_priv.loadCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; super(pkey); }

    /*
    * Check Private DSA Parameters
    */
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!m_priv.checkKey(rng, strong) || m_priv.m_x >= m_priv.groupQ())
            return false;
        
        if (!strong)
            return true;
        
        return signatureConsistencyCheck(rng, m_priv, "EMSA1(SHA-1)");
    }

    alias m_priv this;

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
        assert(dsa.algoName == DSAPublicKey.algoName);
        m_q = &dsa.groupQ();
        m_x = &dsa.getX();
        m_powermod_g_p = FixedBasePowerMod(dsa.groupG(), dsa.groupP());
        m_mod_q = dsa.groupQ().dup;
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
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
            while (k >= *m_q);

            static void handler(shared(Tid) tid, shared(ModularReducer*) mod_q_2, 
                                shared(FixedBasePowerModImpl) powermod_g_p2, shared(BigInt*) k2, shared(BigInt*) r2){ 
                BigInt* K = cast(BigInt*) r2;
                BigInt reduced = (cast(ModularReducer*)mod_q_2).reduce((cast(FixedBasePowerModImpl)powermod_g_p2)(*K));
                *K = reduced.move();
                send(cast(Tid) tid, true); 
            }

            spawn(&handler, cast(shared(Tid))thisTid(), cast(shared(ModularReducer*))&m_mod_q, 
                  cast(shared)*m_powermod_g_p, cast(shared(BigInt*))&k, cast(shared(BigInt*))&r);

            s = inverseMod(k, *m_q);
            bool done = receiveOnly!(bool)();

            s = m_mod_q.multiply(s, mulAdd(*m_x, r, i));
        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_q.bytes());
        r.binaryEncode(&output[output.length / 2 - r.bytes()]);
        s.binaryEncode(&output[output.length - s.bytes()]);
        return output;
    }
private:
	const BigInt* m_q;
	const BigInt* m_x;
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
        m_q = &dsa.groupQ();
        m_y = &dsa.getY();
        m_powermod_g_p = FixedBasePowerMod(dsa.groupG(), dsa.groupP());
        m_powermod_y_p = FixedBasePowerMod(*m_y, dsa.groupP());
        m_mod_p = ModularReducer(dsa.groupP().dup);
        m_mod_q = ModularReducer(dsa.groupQ().dup);
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override bool withRecovery() const { return false; }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t) { throw new InvalidState("Message recovery not supported"); }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        import std.concurrency : spawn, receiveOnly, send, thisTid;
        const BigInt* q = &m_mod_q.getModulus();
        
        if (sig_len != 2*q.bytes() || msg_len > q.bytes())
            return false;
        
        BigInt r = BigInt(sig, q.bytes());
        BigInt s = BigInt(sig + q.bytes(), q.bytes());
        BigInt i = BigInt(msg, msg_len);
        BigInt s_i;
        if (r <= 0 || r >= *q || s <= 0 || s >= *q)
            return false;
        
        s = inverseMod(s, *q);
        static void handler(shared(Tid) tid, shared(FixedBasePowerModImpl) powermod_g_p2, 
                            shared(ModularReducer*) mod_q2, shared(BigInt*) s2, shared(BigInt*) i2, shared(BigInt*) s_i2) 
        { 
            BigInt* K = cast(BigInt*) s_i2;
            BigInt res = (cast(FixedBasePowerModImpl)powermod_g_p2)((*cast(ModularReducer*)mod_q2).multiply(*cast(BigInt*)s2, *cast(BigInt*)i2));
            *K = res.move();
            send(cast(Tid) tid, true); 
        }
        spawn(&handler, cast(shared)thisTid(), cast(shared(FixedBasePowerModImpl))*m_powermod_g_p, cast(shared(ModularReducer*))&m_mod_q, 
              cast(shared(BigInt*))&s, cast(shared(BigInt*))&i, cast(shared(BigInt*))&s_i);
        
        BigInt s_r = (*m_powermod_y_p)(m_mod_q.multiply(s, r));
        bool done = receiveOnly!bool();
        
        s = m_mod_p.multiply(s_i, s_r);
        
        return (m_mod_q.reduce(s) == r);
    }

private:
    const BigInt* m_q;
	const BigInt* m_y;

    FixedBasePowerMod m_powermod_g_p, m_powermod_y_p;
    ModularReducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import memutils.hashmap;

import core.atomic;
private shared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng) {
    size_t fails;
    string[] dsa_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    foreach (dsa; dsa_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = new DSAPrivateKey(rng, DLGroup(dsa));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
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
    
    auto rng = AutoSeededRNG();
    
    BigInt p_bn = BigInt(p);
    BigInt q_bn = BigInt(q);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, q_bn, g_bn);
    auto privkey = new DSAPrivateKey(rng, group.move(), x_bn.move());
    
    auto pubkey = new DSAPublicKey(privkey);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}

static if (!SKIP_DSA_TEST) unittest
{
    logDebug("Testing dsa.d ...");
    size_t fails;
    
    auto rng = AutoSeededRNG();
    
    fails += testPkKeygen(rng);
    
    File dsa_sig = File("../test_data/pubkey/dsa.vec", "r");
    
    fails += runTestsBb(dsa_sig, "DSA Signature", "Signature", true,
                          (ref HashMap!(string, string) m)
                          {
        return dsaSigKat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
    });
    
    testReport("dsa", total_tests, fails);
}

