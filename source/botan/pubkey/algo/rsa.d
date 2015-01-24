/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_RSA):

public import botan.pubkey.pubkey;
public import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import std.concurrency;

/**
* RSA Public Key
*/
class RSAPublicKey
{
public:
    __gshared immutable string algoName = "RSA";

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        m_pub = new IFSchemePublicKey(alg_id, key_bits, algoName);
    }

    /**
    * Create a RSAPublicKey
    * @arg n the modulus
    * @arg e the exponent
    */
    this(BigInt n, BigInt e)
    {
        m_pub = new IFSchemePublicKey(n.move(), e.move(), algoName);
    }

    this(PrivateKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }

    alias m_pub this;

    IFSchemePublicKey m_pub;
}

/**
* RSA Private Key
*/
final class RSAPrivateKey : RSAPublicKey
{
public:
    /*
    * Check Private RSA Parameters
    */
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!m_priv.checkKey(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if ((m_priv.getE() * m_priv.getD()) % lcm(m_priv.getP() - 1, m_priv.getQ() - 1) != 1)
            return false;
        
        return signatureConsistencyCheck(rng, m_priv, "EMSA4(SHA-1)");
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
    {
        m_priv = new IFSchemePrivateKey(rng, alg_id, key_bits, algoName, &checkKey);
        super(m_priv);
    }

    /**
    * Construct a private key from the specified parameters.
    * @param rng = a random number generator
    * @param p = the first prime
    * @param q = the second prime
    * @param e = the exponent
    * @param d = if specified, this has to be d with
    * exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
    * the constructor to calculate it.
    * @param n = if specified, this must be n = p * q. Leave it as 0
    * if you wish to the constructor to calculate it.
    */
    this(RandomNumberGenerator rng, BigInt p, BigInt q, BigInt e, BigInt d = 0, BigInt n = 0)
    {
        m_priv = new IFSchemePrivateKey(rng, p.move(), q.move(), e.move(), d.move(), n.move(), algoName, &checkKey);
        super(m_priv);
    }

    /**
    * Create a new private key with the specified bit length
    * @param rng = the random number generator to use
    * @param bits = the desired bit length of the private key
    * @param exp = the public exponent to be used
    */
    this(RandomNumberGenerator rng, size_t bits, size_t exp = 65537)
    {
        if (bits < 1024)
            throw new InvalidArgument(algoName ~ ": Can't make a key that is only " ~ to!string(bits) ~ " bits long");
        if (exp < 3 || exp % 2 == 0)
            throw new InvalidArgument(algoName ~ ": Invalid encryption exponent");
        BigInt e = exp;
        BigInt p, q, n, d, d1, d2, c;

        do
        {
            p = randomPrime(rng, (bits + 1) / 2, e);
            q = randomPrime(rng, bits - p.bits(), e);
            n = p * q;
        } while (n.bits() != bits);
        
        d = inverseMod(e, lcm(p - 1, q - 1));

        m_priv = new IFSchemePrivateKey(rng, p.move(), q.move(), e.move(), d.move(), n.move(), algoName, &checkKey);
        super(m_priv);
        genCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(IFSchemePrivateKey) pkey; super(pkey); }

    alias m_priv this;

    IFSchemePrivateKey m_priv;
}

/**
* RSA private (decrypt/sign) operation
*/
final class RSAPrivateOperation : Signature, Decryption
{
public:
    this(in PrivateKey pkey, RandomNumberGenerator rng) {
        this(cast(IFSchemePrivateKey) pkey, rng);
    }

    this(in RSAPrivateKey pkey, RandomNumberGenerator rng) {
        this(pkey.m_priv, rng);
    }

    this(in IFSchemePrivateKey rsa, RandomNumberGenerator rng) 
    {
        assert(rsa.algoName == RSAPublicKey.algoName);
        m_n = &rsa.getN();
        m_q = &rsa.getQ();
        m_c = &rsa.getC();
        m_powermod_e_n = FixedExponentPowerMod(rsa.getE(), rsa.getN());
        m_powermod_d1_p = FixedExponentPowerMod(rsa.getD1(), rsa.getP());
        m_powermod_d2_q = FixedExponentPowerMod(rsa.getD2(), rsa.getQ());
        m_mod_p = ModularReducer(rsa.getP());
        BigInt k = BigInt(rng, m_n.bits() - 1);
        m_blinder = Blinder((*m_powermod_e_n)(k), inverseMod(k, *m_n), *m_n);
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }

    override SecureVector!ubyte
        sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);
        
        /* We don't check signatures against powermod_e_n here because
            PKSigner checks verification consistency for all signature
            algorithms.
        */
        
        const BigInt m = BigInt(msg, msg_len);
        const BigInt x = m_blinder.unblind(privateOp(m_blinder.blind(m)));
        return BigInt.encode1363(x, m_n.bytes());
    }

    /*
    * RSA Decryption Operation
    */
    override SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len)
    {
        const BigInt m = BigInt(msg, msg_len);
        const BigInt x = m_blinder.unblind(privateOp(m_blinder.blind(m)));
        
        assert(m == (*m_powermod_e_n)(x), "RSA decrypt passed consistency check");
        
        return BigInt.encodeLocked(x);
    }
private:
    BigInt privateOp()(auto const ref BigInt m) const
    {
        if (m >= *m_n)
            throw new InvalidArgument("RSA private op - input is too large");
        BigInt j1;
        auto tid = spawn((shared(Tid) tid, shared(FixedExponentPowerModImpl) powermod_d1_p2, shared(BigInt*) m2, shared(BigInt*) j1_2)
        { 
            BigInt* ret = cast(BigInt*) j1_2;
            *ret = (cast(FixedExponentPowerModImpl)powermod_d1_p2)(*cast(BigInt*)m2);
            send(cast(Tid)tid, true);
        }, 
        cast(shared) thisTid(), cast(shared(FixedExponentPowerModImpl))*m_powermod_d1_p, cast(shared(BigInt*))&m, cast(shared(BigInt*))&j1);
        BigInt j2 = (cast(FixedExponentPowerModImpl)*m_powermod_d2_q)(m);
        bool done = receiveOnly!bool();
        j1 = m_mod_p.reduce(subMul(j1, j2, *m_c));
        
        return mulAdd(j1, *m_q, j2);
    }

    const BigInt* m_n;
    const BigInt* m_q;
    const BigInt* m_c;
    FixedExponentPowerMod m_powermod_e_n, m_powermod_d1_p, m_powermod_d2_q;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

/**
* RSA public (encrypt/verify) operation
*/
final class RSAPublicOperation : Verification, Encryption
{
public:
    this(in PublicKey pkey) {
        this(cast(IFSchemePublicKey) pkey);
    }

    this(in RSAPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in IFSchemePublicKey rsa)
    {
        assert(rsa.algoName == RSAPublicKey.algoName);
        m_n = &rsa.getN();
        m_powermod_e_n = FixedExponentPowerMod(rsa.getE(), rsa.getN());
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }
    override bool withRecovery() const { return true; }

    override SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encode1363(publicOp(m), m_n.bytes());
    }

    override bool verify(const(ubyte)*, size_t, const(ubyte)*, size_t)
    {
        throw new InvalidState("Message recovery required");
    }

    override SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encodeLocked(publicOp(m));
    }

private:
    BigInt publicOp(const ref BigInt m) const
    {
        if (m >= *m_n)
            throw new InvalidArgument("RSA public op - input is too large");
        return (cast(FixedExponentPowerModImpl)*m_powermod_e_n)(m);
    }

    const BigInt* m_n;
    FixedExponentPowerMod m_powermod_e_n;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import core.atomic;

shared size_t total_tests;


size_t rsaesKat(string e,
                string p,
                string q,
                string msg,
                string padding,
                string nonce,
                string output)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    auto privkey = new RSAPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = new RSAPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    auto enc = scoped!PKEncryptorEME(pubkey, padding);
    auto dec = scoped!PKDecryptorEME(privkey, padding);
    
    return validateEncryption(enc, dec, "RSAES/" ~ padding, msg, nonce, output);
}

size_t rsaSigKat(string e,
                   string p,
                   string q,
                   string msg,
                   string padding,
                   string nonce,
                   string output)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    auto privkey = new RSAPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = new RSAPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "RSA/" ~ padding, msg, rng, nonce, output);
}

size_t rsaSigVerify(string e,
                    string n,
                    string msg,
                    string padding,
                    string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = new RSAPublicKey(n_bn.move(), e_bn.move());
    
    if (padding == "")
        padding = "Raw";
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

size_t testPkKeygen(RandomNumberGenerator rng)
{

    size_t fails;

    auto rsa1024 = scoped!RSAPrivateKey(rng, 1024);
    rsa1024.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);

    fails += validateSaveAndLoad(rsa1024.Scoped_payload, rng);
    
    auto rsa2048 = scoped!RSAPrivateKey(rng, 2048);
    rsa2048.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);
    fails += validateSaveAndLoad(rsa2048.Scoped_payload, rng);

    return fails;
}

unittest
{
    logTrace("Testing rsa.d ...");
    size_t fails = 0;
    
    AutoSeededRNG rng;

    
    File rsa_enc = File("../test_data/pubkey/rsaes.vec", "r");
    File rsa_sig = File("../test_data/pubkey/rsa_sig.vec", "r");
    File rsa_verify = File("../test_data/pubkey/rsa_verify.vec", "r");
    
    
    fails += runTestsBb(rsa_enc, "RSA Encryption", "Ciphertext", true,
                          (string[string] m)
                          {
        return rsaesKat(m["E"], m["P"], m["Q"], m["Msg"],
        m["Padding"], m["Nonce"], m["Ciphertext"]);
    });
    
    fails += runTestsBb(rsa_sig, "RSA Signature", "Signature", true,
                          (string[string] m)
                          {
        return rsaSigKat(m["E"], m["P"], m["Q"], m["Msg"],
        m["Padding"], m["Nonce"], m["Signature"]);
    });
    
    fails += runTestsBb(rsa_verify, "RSA Verify", "Signature", true,
                          (string[string] m)
                          {
        return rsaSigVerify(m["E"], m["N"], m["Msg"],
        m["Padding"], m["Signature"]);
    });
    
    testReport("rsa", total_tests, fails);
}