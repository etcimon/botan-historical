/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.elgamal;

import botan.constants;
static if (BOTAN_HAS_ELGAMAL):

import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.pubkey.workfactor;
import botan.pubkey.pubkey;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import botan.utils.types;

/**
* ElGamal Public Key
*/
class ElGamalPublicKey : DL_SchemePublicKey
{
public:
    @property string algoName() const { return "ElGamal"; }
    DLGroup.Format groupFormat() const { return DLGroup.ANSI_X9_42; }

    size_t maxInputBits() const { return (group_p().bits() - 1); }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        super(alg_id, key_bits, DLGroup.ANSI_X9_42);
    }
    /*
    * ElGamalPublicKey Constructor
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
* ElGamal Private Key
*/
final class ElGamalPrivateKey : ElGamalPublicKey,
                                 DL_SchemePrivateKey
{
public:
    /*
    * Check Private ElGamal Parameters
    */
    bool checkKey(RandomNumberGenerator rng,
                   bool strong) const
    {
        if (!super.checkKey(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        return encryption_consistency_check(rng, this, "EME1(SHA-1)");
    }

    /*
    * ElGamalPrivateKey Constructor
    */
    this(RandomNumberGenerator rng, in DLGroup grp, in BigInt x_arg = 0)
    {
        m_group = grp;
        m_x = x_arg;
        
        if (x == 0)
            m_x.randomize(rng, 2 * dl_work_factor(group_p().bits()));
        
        m_y = powerMod(group_g(), m_x, group_p());
        
        if (x_arg == 0)
            gen_check(rng);
        else
            load_check(rng);
    }

    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        super(alg_id, key_bits, DLGroup.ANSI_X9_42);
        m_y = powerMod(group_g(), m_x, group_p());
        load_check(rng);
    }
}

/**
* ElGamal encryption operation
*/
final class ElGamalEncryptionOperation : Encryption
{
public:
    size_t maxInputBits() const { return mod_p.getModulus().bits() - 1; }


    this(in ElGamalPublicKey key)
    {
        const BigInt p = key.group_p();
        
        m_powermod_g_p = Fixed_Base_Power_Mod(key.groupG(), p);
        m_powermod_y_p = Fixed_Base_Power_Mod(key.getY(), p);
        m_mod_p = ModularReducer(p);
    }

    SecureVector!ubyte encrypt(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        const BigInt p = mod_p.get_modulus();
        
        BigInt m = BigInt(msg, msg_len);
        
        if (m >= p)
            throw new InvalidArgument("ElGamal encryption: Input is too large");

        BigInt k = BigInt(rng, 2 * dl_work_factor(p.bits()));
        
        BigInt a = m_powermod_g_p(k);
        BigInt b = m_mod_p.multiply(m, m_powermod_y_p(k));
        
        SecureVector!ubyte output = SecureVector!ubyte(2*p.bytes());
        a.binaryEncode(&output[p.bytes() - a.bytes()]);
        b.binaryEncode(&output[output.length / 2 + (p.bytes() - b.bytes())]);
        return output;
    }

private:
    Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
    ModularReducer m_mod_p;
}

/**
* ElGamal decryption operation
*/
final class ElGamalDecryptionOperation : Decryption
{
public:
    size_t maxInputBits() const { return mod_p.getModulus().bits() - 1; }

    this(in ElGamalPrivateKey key,
         RandomNumberGenerator rng)
    {
        const BigInt p = key.group_p();
        
        m_powermod_x_p = Fixed_Exponent_Power_Mod(key.getX(), p);
        m_mod_p = ModularReducer(p);
        
        BigInt k = BigInt(rng, p.bits() - 1);
        m_blinder = Blinder(k, m_powermod_x_p(k), p);
    }

    SecureVector!ubyte decrypt(in ubyte* msg, size_t msg_len)
    {
        const BigInt p = m_mod_p.get_modulus();
        
        const size_t p_bytes = p.bytes();
        
        if (msg_len != 2 * p_bytes)
            throw new InvalidArgument("ElGamal decryption: Invalid message");
        
        BigInt a = BigInt(msg, p_bytes);
        BigInt b = BigInt(msg + p_bytes, p_bytes);
        
        if (a >= p || b >= p)
            throw new InvalidArgument("ElGamal decryption: Invalid message");
        
        a = m_blinder.blind(a);
        
        BigInt r = m_mod_p.multiply(b, inverseMod(m_powermod_x_p(a), p));
        
        return BigInt.encodeLocked(m_blinder.unblind(r));
    }
private:
    Fixed_Exponent_Power_Mod m_powermod_x_p;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.pubkey.pubkey;
import botan.codec.hex;
import botan.pubkey.algo.dl_group;
import botan.rng.auto_rng;
import core.atomic;

private __gshared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;
    
    string[] elg_list = ["modp/ietf/1024", "dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    
    foreach (elg; elg_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!ElGamalPrivateKey(rng, ECGroup(OIDS.lookup(elg)));
        key.checkKey(rng, true);
        fails += validate_save_and_load(&key, rng);
    }
    
    return fails;
}

size_t elgamalKat(string p,
                   string g,
                   string x,
                   string msg,
                   string padding,
                   string nonce,
                   string ciphertext)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    const BigInt p_bn = BigInt(p);
    const BigInt g_bn = BigInt(g);
    const BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, g_bn);
    auto privkey = scoped!ElGamalPrivateKey(rng, group, x_bn);
    
    auto pubkey = scoped!ElGamalPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    auto enc = scoped!PK_Encryptor_EME(pubkey, padding);
    auto dec = scoped!PK_Decryptor_EME(privkey, padding);
    
    return validate_encryption(enc, dec, "ElGamal/" ~ padding, msg, nonce, ciphertext);
}

unittest
{
    size_t fails = 0;
    
    AutoSeeded_RNG rng;
    
    fails += testPkKeygen(rng);
    
    File elgamal_enc = File("test_data/pubkey/elgamal.vec", "r");
    
    fails += runTestsBb(elgamal_enc, "ElGamal Encryption", "Ciphertext", true,
                          (string[string] m) {
        return elgamalKat(m["P"], m["G"], m["X"], m["Msg"],
        m["Padding"], m["Nonce"], m["Ciphertext"]);
    });
    
    testReport("elg", total_tests, fails);
}
