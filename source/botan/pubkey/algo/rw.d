/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rw;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_RW):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.utils.parsing;
import botan.utils.types;
import std.algorithm;
import std.concurrency;

/**
* Rabin-Williams Public Key
*/
class RWPublicKey
{
public:
    __gshared immutable string algoName = "RW";

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_pub = new IFSchemePublicKey(alg_id, key_bits, algoName);
    }

    this(BigInt mod, BigInt exponent)
    {
        m_pub = new IFSchemePublicKey(mod.move(), exponent.move(), algoName);
    }

    this(PrivateKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }

    alias m_pub this;

    IFSchemePublicKey m_pub;
}

/**
* Rabin-Williams Private Key
*/
final class RWPrivateKey : RWPublicKey
{
public:
    this(in AlgorithmIdentifier alg_id,
         const ref SecureVector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        m_priv = new IFSchemePrivateKey(rng, alg_id, key_bits, algoName, &checkKey);
        super(m_priv);
    }

    this(RandomNumberGenerator rng,
         BigInt p, BigInt q,
         BigInt e, BigInt d = 0,
         BigInt n = 0)
    {
		m_priv = new IFSchemePrivateKey(rng, p.move(), q.move(), e.move(), d.move(), n.move(), algoName, &checkKey);
        super(m_priv);
    }

    /*
    * Create a Rabin-Williams private key
    */
    this(RandomNumberGenerator rng, size_t bits, size_t exp = 2)
    {
        if (bits < 1024)
            throw new InvalidArgument(algoName ~ ": Can't make a key that is only " ~
                                       to!string(bits) ~ " bits long");
        if (exp < 2 || exp % 2 == 1)
            throw new InvalidArgument(algoName ~ ": Invalid encryption exponent");

        BigInt p, q, e, d, n, d1, d2;

        e = exp;
        
        do
        {
            p = randomPrime(rng, (bits + 1) / 2, e / 2, 3, 4);
            q = randomPrime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
            n = p * q;
        } while (n.bits() != bits);
        
        d = inverseMod(e, lcm(p - 1, q - 1) >> 1);

		m_priv = new IFSchemePrivateKey(rng, p.move(), q.move(), e.move(), d.move(), n.move(), algoName, &checkKey);

        super(m_priv);
        genCheck(rng);
    }

    /*
    * Check Private Rabin-Williams Parameters
    */
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!m_priv.checkKey(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if ((m_priv.getE() * m_priv.getD()) % (lcm(m_priv.getP() - 1, m_priv.getQ() - 1) / 2) != 1)
            return false;
        
        return signatureConsistencyCheck(rng, m_priv, "EMSA2(SHA-1)");
    }

    alias m_priv this;

    this(PrivateKey pkey) { m_priv = cast(IFSchemePrivateKey) pkey; super(m_priv); }


    IFSchemePrivateKey m_priv;
}

/**
* Rabin-Williams Signature Operation
*/
final class RWSignatureOperation : Signature
{
public:
    this(in RWPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in PrivateKey pkey) {
        this(cast(IFSchemePrivateKey) pkey);
    }

    this(in IFSchemePrivateKey rw) 
    {
        assert(rw.algoName == RWPublicKey.algoName);
        m_n = &rw.getN();
        m_e = &rw.getE();
        m_q = &rw.getQ();
        m_c = &rw.getC();
        m_powermod_d1_p = FixedExponentPowerMod(rw.getD1(), rw.getP());
        m_powermod_d2_q = FixedExponentPowerMod(rw.getD2(), rw.getQ());
        m_mod_p = ModularReducer(rw.getP());
        m_blinder = Blinder.init;
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);

        if (!m_blinder.initialized()) {
            BigInt k = BigInt(rng, std.algorithm.min(160, m_n.bits() - 1));
            m_blinder = Blinder(powerMod(k, *m_e, *m_n), inverseMod(k, *m_n), *m_n);
        }

        BigInt i = BigInt(msg, msg_len);
        
        if (i >= *m_n || i % 16 != 12)
            throw new InvalidArgument("Rabin-Williams: invalid input");
        
        if (jacobi(i, *m_n) != 1)
            i >>= 1;
        
        i = m_blinder.blind(i);

        BigInt j1;

        auto tid = spawn((shared Tid tid, shared(FixedExponentPowerModImpl) powermod_d1_p2, shared(BigInt*) i2, shared(BigInt*) j1_2) 
        {
            BigInt* ret = cast(BigInt*)j1_2;
            *ret = (cast(FixedExponentPowerModImpl)powermod_d1_p2)(*cast(BigInt*)i2);
            send(cast(Tid)tid, true); 
        }, 
        cast(shared)thisTid(), cast(shared)*m_powermod_d1_p, cast(shared)&i, cast(shared)&j1);
        const BigInt j2 = (*m_powermod_d2_q)(i);
        bool ok = receiveOnly!bool();
        
        j1 = m_mod_p.reduce(subMul(j1, j2, *m_c));
        
        BigInt r = m_blinder.unblind(mulAdd(j1, *m_q, j2));
        
		BigInt cmp2 = *m_n - r;
        BigInt min_val = r.move();
        if (cmp2 < min_val)
            min_val = cmp2.move();

        return BigInt.encode1363(min_val, m_n.bytes());
    }
private:
    const BigInt* m_n;
    const BigInt* m_e;
    const BigInt* m_q;
    const BigInt* m_c;

    FixedExponentPowerMod m_powermod_d1_p, m_powermod_d2_q;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

/**
* Rabin-Williams Verification Operation
*/
final class RWVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(IFSchemePublicKey) pkey);
    }

    this(in RWPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in IFSchemePublicKey rw)
    {
        assert(rw.algoName == RWPublicKey.algoName);
        m_n = &rw.getN();
        m_powermod_e_n = FixedExponentPowerMod(rw.getE(), rw.getN());
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }
    override bool withRecovery() const { return true; }

    override bool verify(const(ubyte)*, size_t, const(ubyte)*, size_t)
    {
        throw new InvalidState("Message recovery required");
    }

    override SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        
        if ((m > (*m_n >> 1)) || m.isNegative())
            throw new InvalidArgument("RW signature verification: m > n / 2 || m < 0");
        
        BigInt r = (*m_powermod_e_n)(m);
        if (r % 16 == 12)
            return BigInt.encodeLocked(r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        r = (*m_n) - r;
        if (r % 16 == 12)
            return BigInt.encodeLocked(r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        throw new InvalidArgument("RW signature verification: Invalid signature");
    }

private:
    const BigInt* m_n;
    FixedExponentPowerMod m_powermod_e_n;
}


static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;
__gshared immutable string padding = "EMSA2(SHA-1)";

size_t testPkKeygen(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails;
    auto rw1024 = scoped!RWPrivateKey(rng, 1024);
    rw1024.checkKey(rng, true);
    fails += validateSaveAndLoad(rw1024.Scoped_payload, rng);
    return fails;
}
size_t rwSigKat(string e,
                  string p,
                  string q,
                  string msg,
                  string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    auto privkey = new RWPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = new RWPublicKey(privkey);
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "RW/" ~ padding, msg, rng, signature);
}

size_t rwSigVerify(string e,
                     string n,
                     string msg,
                     string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = new RWPublicKey(n_bn.move(), e_bn.move());
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

unittest
{
    logDebug("Testing rw.d ...");
    size_t fails = 0;
    
    AutoSeededRNG rng;
    
    fails += testPkKeygen(rng);
    
    File rw_sig = File("../test_data/pubkey/rw_sig.vec", "r");
    File rw_verify = File("../test_data/pubkey/rw_verify.vec", "r");
    
    fails += runTestsBb(rw_sig, "RW Signature", "Signature", true,
                          (ref HashMap!(string, string) m) {
        return rwSigKat(m["E"], m["P"], m["Q"], m["Msg"], m["Signature"]);
    });
    
    fails += runTestsBb(rw_verify, "RW Verify", "Signature", true,
                          (ref HashMap!(string, string) m) {
        return rwSigVerify(m["E"], m["N"], m["Msg"], m["Signature"]);
    });

    testReport("rw", total_tests, fails);
}