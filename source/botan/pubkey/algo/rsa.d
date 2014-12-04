/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rsa;

import botan.constants;
static if (BOTAN_HAS_RSA):

import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import future;

/**
* RSA Public Key
*/
class RSAPublicKey : IF_SchemePublicKey
{
public:
    @property string algoName() const { return "RSA"; }

    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits) 
    {
        super(alg_id, key_bits);
    }

    /**
    * Create a RSAPublicKey
    * @arg n the modulus
    * @arg e the exponent
    */
    this(in BigInt n, in BigInt e)
    {
        super(n, e);
    }

protected:
    this() {}
}

/**
* RSA Private Key
*/
final class RSAPrivateKey : RSAPublicKey,
                               IF_SchemePrivateKey
{
public:
    /*
    * Check Private RSA Parameters
    */
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!super.checkKey(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if ((m_e * m_d) % lcm(m_p - 1, m_q - 1) != 1)
            return false;
        
        return signatureConsistencyCheck(rng, this, "EMSA4(SHA-1)");
    }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
    {
        super(rng, alg_id, key_bits);
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
    this(RandomNumberGenerator rng, in BigInt p, in BigInt q, in BigInt e, in BigInt d = 0, in BigInt n = 0)
    {
        super(rng, p, q, e, d, n);
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
            throw new InvalidArgument(algo_name ~ ": Can't make a key that is only " ~ to!string(bits) ~ " bits long");
        if (exp < 3 || exp % 2 == 0)
            throw new InvalidArgument(algo_name ~ ": Invalid encryption exponent");
        
        m_e = exp;
        
        do
        {
            m_p = randomPrime(rng, (bits + 1) / 2, m_e);
            m_q = randomPrime(rng, bits - m_p.bits(), m_e);
            m_n = m_p * m_q;
        } while (m_n.bits() != bits);
        
        m_d = inverseMod(e, lcm(m_p - 1, m_q - 1));
        m_d1 = m_d % (m_p - 1);
        m_d2 = m_d % (m_q - 1);
        m_c = inverseMod(m_q, m_p);
        
        genCheck(rng);
    }
}

/**
* RSA private (decrypt/sign) operation
*/
final class RSAPrivateOperation : Signature, Decryption
{
public:
    this(in RSAPrivateKey rsa, RandomNumberGenerator rng) 
    {
        m_n = rsa.getN();
        m_q = rsa.getQ();
        m_c = rsa.getC();
        m_powermod_e_n = FixedExponentPowerMod(rsa.getE(), rsa.getN());
        m_powermod_d1_p = FixedExponentPowerMod(rsa.getD1(), rsa.getP());
        m_powermod_d2_q = FixedExponentPowerMod(rsa.getD2(), rsa.getQ());
        m_mod_p = rsa.getP();
        BigInt k = BigInt(rng, m_n.bits() - 1);
        m_blinder = Blinder(m_powermod_e_n(k), inverseMod(k, m_n), m_n);
    }

    size_t maxInputBits() const { return (n.bits() - 1); }

    SecureVector!ubyte
        sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);
        
        /* We don't check signatures against powermod_e_n here because
            PKSigner checks verification consistency for all signature
            algorithms.
        */
        
        const BigInt m = BigInt(msg, msg_len);
        const BigInt x = m_blinder.unblind(privateOp(m_blinder.blind(m)));
        return BigInt.encode1363(x, n.bytes());
    }

    /*
    * RSA Decryption Operation
    */
    SecureVector!ubyte decrypt(in ubyte* msg, size_t msg_len)
    {
        const BigInt m = BigInt(msg, msg_len);
        const BigInt x = m_blinder.unblind(privateOp(m_blinder.blind(m)));
        
        assert(m == m_powermod_e_n(x), "RSA decrypt passed consistency check");
        
        return BigInt.encodeLocked(x);
    }
private:
    BigInt privateOp(in BigInt m) const
    {
        if (m >= m_n)
            throw new InvalidArgument("RSA private op - input is too large");

        import std.concurrency : spawn, receiveOnly, thidTid, send;
        auto tid = spawn((Tid tid, FixedExponentPowerMod powermod_d1_p2, BigInt m2) { send(tid, powermod_d1_p2(m2)); }, 
                            thisTid, m_powermod_d1_p, m);
        BigInt j2 = m_powermod_d2_q(m);
        BigInt j1 = receiveOnly!BigInt();
        
        j1 = m_mod_p.reduce(subMul(j1, j2, c));
        
        return mulAdd(j1, q, j2);
    }

    const BigInt m_n;
    const BigInt m_q;
    const BigInt m_c;
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
    this(in RSAPublicKey rsa)
    {
        m_n = rsa.getN();
        m_powermod_e_n = FixedExponentPowerMod(rsa.getE(), rsa.getN());
    }

    size_t maxInputBits() const { return (n.bits() - 1); }
    bool withRecovery() const { return true; }

    SecureVector!ubyte encrypt(in ubyte* msg, size_t msg_len, RandomNumberGenerator)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encode1363(publicOp(m), m_n.bytes());
    }

    SecureVector!ubyte verifyMr(in ubyte* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encodeLocked(publicOp(m));
    }

private:
    BigInt publicOp(in BigInt m) const
    {
        if (m >= m_n)
            throw new InvalidArgument("RSA public op - input is too large");
        return m_powermod_e_n(m);
    }

    const BigInt n;
    FixedExponentPowerMod m_powermod_e_n;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import core.atomic;

__gshared size_t total_tests;


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
    
    auto privkey = scoped!RSAPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = scoped!RSAPublicKey(privkey);
    
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
    
    auto privkey = scoped!RSAPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = scoped!RSAPublicKey(privkey);
    
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
    
    auto key = scoped!RSAPublicKey(n_bn, e_bn);
    
    if (padding == "")
        padding = "Raw";
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

size_t testPkKeygen(RandomNumberGenerator rng)
{

    auto rsa1024 = scoped!RSAPrivateKey(rng, 1024);
    rsa1024.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);
    fails += validateSaveAndLoad(&rsa1024, rng);
    
    auto rsa2048 = scoped!RSAPrivateKey(rng, 2048);
    rsa2048.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);
    fails += validateSaveAndLoad(&rsa2048, rng);

}

unittest
{
    size_t fails = 0;
    
    AutoSeededRNG rng;

    
    File rsa_enc = File("test_data/pubkey/rsaes.vec", "r");
    File rsa_sig = File("test_data/pubkey/rsa_sig.vec", "r");
    File rsa_verify = File("test_data/pubkey/rsa_verify.vec", "r");
    
    
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