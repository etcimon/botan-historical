/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dsa;

import botan.constants;
static if (BOTAN_HAS_DSA):

import botan.pubkey.algo.dl_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;

/**
* DSA Public Key
*/
class DSA_PublicKey : DL_Scheme_PublicKey
{
public:
	@property string algo_name() const { return "DSA"; }

	DL_Group.Format group_format() const { return DL_Group.ANSI_X9_57; }
	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return group_q().bytes(); }
	size_t max_input_bits() const { return group_q().bits(); }

	this(in Algorithm_Identifier alg_id,
					  in Secure_Vector!ubyte key_bits) 
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_57);
	}

	/*
	* DSA_PublicKey Constructor
	*/
	this(in DL_Group grp, in BigInt y1)
	{
		m_group = grp;
		m_y = y1;
	}
protected:
	this() {}
}

/**
* DSA Private Key
*/
final class DSA_PrivateKey : DSA_PublicKey,
							 DL_Scheme_PrivateKey
{
public:
	/*
	* Create a DSA private key
	*/
	this(RandomNumberGenerator rng, in DL_Group dl_group, in BigInt private_key = 0)
	{
		m_group = dl_group;
		m_x = private_key;
		
		if (m_x == 0)
			m_x = BigInt.random_integer(rng, 2, group_q() - 1);
		
		m_y = power_mod(group_g(), m_x, group_p());
		
		if (private_key == 0)
			gen_check(rng);
		else
			load_check(rng);
	}

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits, RandomNumberGenerator rng)
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_57);
		m_y = power_mod(group_g(), m_x, group_p());
		
		load_check(rng);
	}

	/*
	* Check Private DSA Parameters
	*/
	bool check_key(RandomNumberGenerator rng, bool strong) const
	{
		if (!super.check_key(rng, strong) || m_x >= group_q())
			return false;
		
		if (!strong)
			return true;
		
		return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
	}

}

/**
* Object that can create a DSA signature
*/
final class DSA_Signature_Operation : Signature
{
public:
	this(in DSA_PrivateKey dsa)
	{ 
		m_q = dsa.group_q();
		m_x = dsa.get_x();
		m_powermod_g_p = Fixed_Base_Power_Mod(dsa.group_g(), dsa.group_p());
		m_mod_q = dsa.group_q();
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_q.bytes(); }
	size_t max_input_bits() const { return m_q.bits(); }

	Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
	{
		import std.concurrency : spawn, receiveOnly, thisTid, send;
		rng.add_entropy(msg, msg_len);
		
		BigInt i = BigInt(msg, msg_len);
		BigInt r = 0, s = 0;
		
		while (r == 0 || s == 0)
		{
			BigInt k;
			do
				k.randomize(rng, m_q.bits());
			while (k >= m_q);
			
			auto tid = spawn((Tid tid, Fixed_Base_Power_Mod powermod_g_p2, BigInt k2){ send(tid, m_mod_q.reduce(powermod_g_p2(k2))); }, thisTid, m_powermod_g_p, k);
			
			s = inverse_mod(k, m_q);

			r = receiveOnly!BigInt();

			s = m_mod_q.multiply(s, mul_add(m_x, r, i));
		}
		
		Secure_Vector!ubyte output = Secure_Vector!ubyte(2*m_q.bytes());
		r.binary_encode(&output[output.length / 2 - r.bytes()]);
		s.binary_encode(&output[output.length - s.bytes()]);
		return output;
	}
private:
	const BigInt m_q;
	const BigInt m_x;
	Fixed_Base_Power_Mod m_powermod_g_p;
	Modular_Reducer m_mod_q;
}

/**
* Object that can verify a DSA signature
*/
final class DSA_Verification_Operation : Verification
{
public:

	this(in DSA_PublicKey dsa) 
	{
		m_q = dsa.group_q();
		m_y = dsa.get_y();
		m_powermod_g_p = Fixed_Base_Power_Mod(dsa.group_g(), dsa.group_p());
		m_powermod_y_p = Fixed_Base_Power_Mod(y, dsa.group_p());
		m_mod_p = Modular_Reducer(dsa.group_p());
		m_mod_q = Modular_Reducer(dsa.group_q());
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_q.bytes(); }
	size_t max_input_bits() const { return m_q.bits(); }

	bool with_recovery() const { return false; }

	bool verify(in ubyte* msg, size_t msg_len,
	            in ubyte* sig, size_t sig_len)
	{
		import std.concurrency : spawn, receiveOnly, send, thisTid;
		const BigInt q = mod_q.get_modulus();
		
		if (sig_len != 2*q.bytes() || msg_len > q.bytes())
			return false;
		
		BigInt r = BigInt(sig, q.bytes());
		BigInt s = BigInt(sig + q.bytes(), q.bytes());
		BigInt i = BigInt(msg, msg_len);
		
		if (r <= 0 || r >= q || s <= 0 || s >= q)
			return false;
		
		s = inverse_mod(s, q);
		
		auto tid = spawn((Tid tid, Fixed_Base_Power_Mod powermod_g_p2, BigInt mod_q2, BigInt s2, BigInt i2) 
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

	Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
	Modular_Reducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;

import core.atomic;
private __gshared size_t total_tests;

size_t test_pk_keygen(RandomNumberGenerator rng) {
	size_t fails;
	string[] dsa_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
	foreach (dsa; dsa_list) {
		atomicOp!"+="(total_tests, 1);
		auto key = scoped!DSA_PrivateKey(rng, DL_Group(dsa));
		key.check_key(rng, true);
		fails += validate_save_and_load(&key, rng);
	}
	
	return fails;
}

size_t dsa_sig_kat(string p,
                   string q,
                   string g,
                   string x,
                   string hash,
                   string msg,
                   string nonce,
                   string signature)
{
	atomicOp!"+="(total_tests, 1);
	
	AutoSeeded_RNG rng;
	
	BigInt p_bn = BigInt(p);
	BigInt q_bn = BigInt(q);
	BigInt g_bn = BigInt(g);
	BigInt x_bn = BigInt(x);
	
	DL_Group group = DL_Group(p_bn, q_bn, g_bn);
	auto privkey = scoped!DSA_PrivateKey(rng, group, x_bn);
	
	auto pubkey = scoped!DSA_PublicKey(privkey);
	
	const string padding = "EMSA1(" ~ hash ~ ")";
	
	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);
	
	return validate_signature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}

unittest
{
	size_t fails;
	
	AutoSeeded_RNG rng;
	
	fails += test_pk_keygen(rng);
	
	File dsa_sig = File("test_data/pubkey/dsa.vec", "r");
	
	fails += run_tests_bb(dsa_sig, "DSA Signature", "Signature", true,
	                      (string[string] m)
	                      {
		return dsa_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
	});
	
	test_report("dsa", total_tests, fails);
}

