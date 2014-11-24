/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rw;

import botan.constants;
static if (BOTAN_HAS_RW):

import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.utils.parsing;
import botan.utils.types;
import std.algorithm;

/**
* Rabin-Williams Public Key
*/
class RW_PublicKey : IF_Scheme_PublicKey
{
public:
    @property string algo_name() const { return "RW"; }

    this(in Algorithm_Identifier alg_id,
                     in Secure_Vector!ubyte key_bits)
    {
        super(alg_id, key_bits);
    }

    this(in BigInt mod, in BigInt exponent)
    {
        super(mod, exponent);
    }

protected:
    this() {}
}

/**
* Rabin-Williams Private Key
*/
final class RW_PrivateKey : RW_PublicKey,
                              IF_Scheme_PrivateKey
{
public:
    this(in Algorithm_Identifier alg_id,
         in Secure_Vector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        super(rng, alg_id, key_bits);
    }

    this(RandomNumberGenerator rng,
         in BigInt p, in BigInt q,
         in BigInt e, in BigInt d = 0,
         in BigInt n = 0)
    {
        super(rng, p, q, e, d, n);
    }

    /*
    * Create a Rabin-Williams private key
    */
    this(RandomNumberGenerator rng, size_t bits, size_t exp = 2)
    {
        if (bits < 1024)
            throw new Invalid_Argument(algo_name ~ ": Can't make a key that is only " ~
                                       to!string(bits) ~ " bits long");
        if (exp < 2 || exp % 2 == 1)
            throw new Invalid_Argument(algo_name ~ ": Invalid encryption exponent");
        
        m_e = exp;
        
        do
        {
            m_p = random_prime(rng, (bits + 1) / 2, m_e / 2, 3, 4);
            m_q = random_prime(rng, bits - m_p.bits(), m_e / 2, ((m_p % 8 == 3) ? 7 : 3), 8);
            m_n = m_p * m_q;
        } while (m_n.bits() != bits);
        
        m_d = inverse_mod(m_e, lcm(m_p - 1, m_q - 1) >> 1);
        m_d1 = m_d % (m_p - 1);
        m_d2 = m_d % (m_q - 1);
        m_c = inverse_mod(m_q, m_p);
        
        gen_check(rng);
    }

    /*
    * Check Private Rabin-Williams Parameters
    */
    bool check_key(RandomNumberGenerator rng, bool strong) const
    {
        if (!super.check_key(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if ((m_e * m_d) % (lcm(m_p - 1, m_q - 1) / 2) != 1)
            return false;
        
        return signature_consistency_check(rng, this, "EMSA2(SHA-1)");
    }
}

/**
* Rabin-Williams Signature Operation
*/
final class RW_Signature_Operation : Signature
{
public:
    this(in RW_PrivateKey rw) 
    {
        m_n = rw.get_n();
        m_e = rw.get_e();
        m_q = rw.get_q();
        m_c = rw.get_c();
        m_powermod_d1_p = Fixed_Exponent_Power_Mod(rw.get_d1(), rw.get_p());
        m_powermod_d2_q = Fixed_Exponent_Power_Mod(rw.get_d2(), rw.get_q());
        m_mod_p = Fixed_Exponent_Power_Mod(rw.get_p());
    }

    size_t max_input_bits() const { return (m_n.bits() - 1); }

    Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.add_entropy(msg, msg_len);
        
        if (!blinder.initialized())
        {
            BigInt k = BigInt(rng, std.algorithm.min(160, m_n.bits() - 1));
            m_blinder = Blinder(power_mod(k, m_e, m_n), inverse_mod(k, m_n), m_n);
        }
        
        BigInt i = BigInt(msg, msg_len);
        
        if (i >= m_n || i % 16 != 12)
            throw new Invalid_Argument("Rabin-Williams: invalid input");
        
        if (jacobi(i, m_n) != 1)
            i >>= 1;
        
        i = m_blinder.blind(i);

        import std.concurrency : spawn, thisTid, send, receiveOnly;

        auto tid = spawn((Tid tid, Fixed_Exponent_Power_Mod powermod_d1_p2, BigInt i2) 
                         { send(tid, powermod_d1_p2(i2)); }, thisTid, m_powermod_d1_p, i);
        const BigInt j2 = m_powermod_d2_q(i);
        BigInt j1 = receiveOnly!BigInt();
        
        j1 = m_mod_p.reduce(sub_mul(j1, j2, m_c));
        
        const BigInt r = m_blinder.unblind(mul_add(j1, m_q, j2));
        
        return BigInt.encode_1363(std.algorithm.min(r, m_n - r), n.bytes());
    }
private:
    const BigInt m_n;
    const BigInt m_e;
    const BigInt m_q;
    const BigInt m_c;

    Unique!Fixed_Exponent_Power_Mod m_powermod_d1_p, m_powermod_d2_q;
    Modular_Reducer m_mod_p;
    Blinder m_blinder;
}

/**
* Rabin-Williams Verification Operation
*/
final class RW_Verification_Operation : Verification
{
public:
    this(in RW_PublicKey rw)
    {
        m_n = rw.get_n();
        m_powermod_e_n = Fixed_Exponent_Power_Mod(rw.get_e(), rw.get_n());
    }

    size_t max_input_bits() const { return (m_n.bits() - 1); }
    bool with_recovery() const { return true; }

    Secure_Vector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        
        if ((m > (m_n >> 1)) || m.is_negative())
            throw new Invalid_Argument("RW signature verification: m > n / 2 || m < 0");
        
        BigInt r = m_powermod_e_n(m);
        if (r % 16 == 12)
            return BigInt.encode_locked(r);
        if (r % 8 == 6)
            return BigInt.encode_locked(2*r);
        
        r = m_n - r;
        if (r % 16 == 12)
            return BigInt.encode_locked(r);
        if (r % 8 == 6)
            return BigInt.encode_locked(2*r);
        
        throw new Invalid_Argument("RW signature verification: Invalid signature");
    }

private:
    const BigInt m_n;
    Fixed_Exponent_Power_Mod powermod_e_n;
}


static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import core.atomic;

__gshared size_t total_tests;
__gshared immutable string padding = "EMSA2(SHA-1)";

size_t test_pk_keygen(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails;
    auto rw1024 = scoped!RW_PrivateKey(rng, 1024);
    rw1024.check_key(rng, true);
    fails += validate_save_and_load(&rw1024, rng);
    return fails;
}
size_t rw_sig_kat(string e,
                  string p,
                  string q,
                  string msg,
                  string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    auto privkey = scoped!RW_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = scoped!RW_PublicKey(privkey);
    
    PK_Verifier verify = PK_Verifier(pubkey, padding);
    PK_Signer sign = PK_Signer(privkey, padding);
    
    return validate_signature(verify, sign, "RW/" ~ padding, msg, rng, signature);
}

size_t rw_sig_verify(string e,
                     string n,
                     string msg,
                     string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeeded_RNG rng;
    
    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = scoped!RW_PublicKey(n_bn, e_bn);
    
    PK_Verifier verify = PK_Verifier(key, padding);
    
    if (!verify.verify_message(hex_decode(msg), hex_decode(signature)))
        return 1;
    return 0;
}

unittest
{
    size_t fails = 0;
    
    AutoSeeded_RNG rng;
    
    fails += test_pk_keygen(rng);
    
    File rw_sig = File("test_data/pubkey/rw_sig.vec", "r");
    File rw_verify = File("test_data/pubkey/rw_verify.vec", "r");
    
    fails += run_tests_bb(rw_sig, "RW Signature", "Signature", true,
                          (string[string] m) {
        return rw_sig_kat(m["E"], m["P"], m["Q"], m["Msg"], m["Signature"]);
    });
    
    fails += run_tests_bb(rw_verify, "RW Verify", "Signature", true,
                          (string[string] m) {
        return rw_sig_verify(m["E"], m["N"], m["Msg"], m["Signature"]);
    });

    test_report("rw", total_tests, fails);
}