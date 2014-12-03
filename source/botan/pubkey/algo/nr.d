/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.nr;

import botan.constants;
static if (BOTAN_HAS_NYBERG_RUEPPEL):

import botan.pubkey.algo.dl_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;

/**
* Nyberg-Rueppel Public Key
*/
class NRPublicKey : DL_SchemePublicKey
{
public:
    @property string algoName() const { return "NR"; }

    DLGroup.Format groupFormat() const { return DLGroup.ANSI_X9_57; }

    size_t messageParts() const { return 2; }
    size_t messagePartSize() const { return group_q().bytes(); }
    size_t maxInputBits() const { return (group_q().bits() - 1); }


    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits) 
    {
        super(alg_id, key_bits, DLGroup.ANSI_X9_57);
    }

    /*
    * NRPublicKey Constructor
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
* Nyberg-Rueppel Private Key
*/
final class NRPrivateKey : NRPublicKey,
                             DL_SchemePrivateKey
{
public:
    /*
* Check Private Nyberg-Rueppel Parameters
*/
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (!super.checkKey(rng, strong) || m_x >= group_q())
            return false;
        
        if (!strong)
            return true;
        
        return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
    }


    /*
    * Create a NR private key
    */
    this(RandomNumberGenerator rng, in DLGroup grp, in BigInt x_arg)
    {
        m_group = grp;
        m_x = x_arg;
        
        if (m_x == 0)
            m_x = BigInt.randomInteger(rng, 2, group_q() - 1);
        
        m_y = powerMod(group_g(), m_x, group_p());
        
        if (x_arg == 0)
            gen_check(rng);
        else
            load_check(rng);
    }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    { 
        super(alg_id, key_bits, DLGroup.ANSI_X9_57);
        m_y = powerMod(group_g(), m_x, group_p());
        
        load_check(rng);
    }

}

/**
* Nyberg-Rueppel signature operation
*/
final class NRSignatureOperation : Signature
{
public:
    size_t messageParts() const { return 2; }
    size_t messagePartSize() const { return m_q.bytes(); }
    size_t maxInputBits() const { return (m_q.bits() - 1); }

    this(in NRPrivateKey nr)
    {
        m_q = nr.groupQ();
        m_x = nr.getX();
        m_powermod_g_p = Fixed_Base_Power_Mod(nr.groupG(), nr.groupP());
        m_mod_q = ModularReducer(nr.groupQ());
    }

    SecureVector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);
        
        BigInt f = BigInt(msg, msg_len);
        
        if (f >= m_q)
            throw new InvalidArgument("NR_Signature_Operation: Input is out of range");
        
        BigInt c, d;
        
        while (c == 0)
        {
            BigInt k;
            do
                k.randomize(rng, m_q.bits());
            while (k >= m_q);
            
            c = m_mod_q.reduce(m_powermod_g_p(k) + f);
            d = m_mod_q.reduce(k - x * c);
        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_q.bytes());
        c.binaryEncode(&output[output.length / 2 - c.bytes()]);
        d.binaryEncode(&output[output.length - d.bytes()]);
        return output;
    }
private:
    const BigInt m_q;
    const BigInt m_x;
    Fixed_Base_Power_Mod m_powermod_g_p;
    ModularReducer m_mod_q;
}

/**
* Nyberg-Rueppel verification operation
*/
final class NRVerificationOperation : Verification
{
public:
    this(in NRPublicKey nr) 
    {
        m_q = nr.groupQ();
        m_y = nr.getY();
        m_powermod_g_p = Fixed_Base_Power_Mod(nr.groupG(), nr.groupP());
        m_powermod_y_p = Fixed_Base_Power_Mod(y, nr.groupP());
        m_mod_p = ModularReducer(nr.groupP());
        m_mod_q = ModularReducer(nr.groupQ());
    }

    size_t messageParts() const { return 2; }
    size_t messagePartSize() const { return m_q.bytes(); }
    size_t maxInputBits() const { return (m_q.bits() - 1); }

    bool withRecovery() const { return true; }

    SecureVector!ubyte verifyMr(in ubyte* msg, size_t msg_len)
    {
        const BigInt q = m_mod_q.get_modulus(); // todo: why not use m_q?
        size_t msg_len = msg.length;
        if (msg_len != 2*q.bytes())
            throw new InvalidArgument("NR verification: Invalid signature");
        
        BigInt c = BigInt(msg, q.bytes());
        BigInt d = BigInt(msg + q.bytes(), q.bytes());
        
        if (c.isZero() || c >= q || d >= q)
            throw new InvalidArgument("NR verification: Invalid signature");
        import std.concurrency : spawn, receiveOnly, send, thisTid;

        auto tid = spawn((Tid tid, Fixed_Base_Power_Mod powermod_y_p2, BigInt c2) { send(tid, powermod_y_p2(c2)); }, thisTid, m_powermod_y_p, c );
        BigInt g_d = m_powermod_g_p(d);
        
        BigInt i = m_mod_p.multiply(g_d, receiveOnly!BigInt());
        return BigInt.encodeLocked(m_mod_q.reduce(c - i));
    }
private:
    const BigInt m_q;
    const BigInt m_y;

    Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
    ModularReducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.pubkey.pubkey;
import botan.codec.hex;
import botan.rng.auto_rng;
import core.atomic;

private __gshared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{    
    size_t fails;
    string[] nr_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    
    foreach (nr; nr_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!ElGamalPrivateKey(rng, ECGroup(OIDS.lookup(nr)));
        key.checkKey(rng, true);
        fails += validate_save_and_load(&key, rng);
    }
    
    return fails;
}

size_t nrSigKat(string p, string q, string g, string x, 
                  string hash, string msg, string nonce, string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    BigInt p_bn = BigInt(p);
    BigInt q_bn = BigInt(q);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, q_bn, g_bn);
    
    auto privkey = scoped!NRPrivateKey(rng, group, x_bn);
    
    auto pubkey = scoped!NRPublicKey(privkey);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validate_signature(verify, sign, "nr/" ~ hash, msg, rng, nonce, signature);
}

unittest
{
    size_t fails = 0;
    
    AutoSeeded_RNG rng;
    
    fails += testPkKeygen(rng);
    
    File nr_sig = File("test_data/pubkey/nr.vec", "r");
    
    fails += runTestsBb(nr_sig, "NR Signature", "Signature", true,
                          (string[string] m) {
        return nrSigKat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
    });
    
    testReport("nr", total_tests, fails);
}