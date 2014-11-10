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
import future;
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
	this(in DL_Group grp, const ref BigInt y1)
	{
		group = grp;
		y = y1;
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
	this(RandomNumberGenerator rng,
	     const ref DL_Group dl_group,
	     const ref BigInt private_key = 0)
	{
		group = dl_group;
		x = private_key;
		
		if (x == 0)
			x = BigInt.random_integer(rng, 2, group_q() - 1);
		
		y = power_mod(group_g(), x, group_p());
		
		if (private_key == 0)
			gen_check(rng);
		else
			load_check(rng);
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     RandomNumberGenerator rng)
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_57);
		y = power_mod(group_g(), x, group_p());
		
		load_check(rng);
	}

	/*
	* Check Private DSA Parameters
	*/
	bool check_key(RandomNumberGenerator rng, bool strong) const
	{
		if (!super.check_key(rng, strong) || x >= group_q())
			return false;
		
		if (!strong)
			return true;
		
		return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
	}


	bool check_key(RandomNumberGenerator rng, bool strong) const;
}

/**
* Object that can create a DSA signature
*/
final class DSA_Signature_Operation : Signature
{
public:
	this(in DSA_PrivateKey dsa)
	{ 
		q = dsa.group_q();
		x = dsa.get_x();
		powermod_g_p = Fixed_Base_Power_Mod(dsa.group_g(), dsa.group_p());
		mod_q = dsa.group_q();
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return q.bytes(); }
	size_t max_input_bits() const { return q.bits(); }

	Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len,
		 					    RandomNumberGenerator rng)
	{
		import std.concurrency : spawn, receiveOnly, thisTid, send;
		rng.add_entropy(msg, msg_len);
		
		BigInt i = BigInt(msg, msg_len);
		BigInt r = 0, s = 0;
		
		while(r == 0 || s == 0)
		{
			BigInt k;
			do
				k.randomize(rng, q.bits());
			while(k >= q);
			
			auto tid = spawn((Tid tid, Fixed_Base_Power_Mod powermod_g_p2, BigInt k2){ send(tid, mod_q.reduce(powermod_g_p2(k2))); }, thisTid, powermod_g_p, k);
			
			s = inverse_mod(k, q);

			r = receiveOnly!BigInt();

			s = mod_q.multiply(s, mul_add(x, r, i));
		}
		
		Secure_Vector!ubyte output = Secure_Vector!ubyte(2*q.bytes());
		r.binary_encode(&output[output.length / 2 - r.bytes()]);
		s.binary_encode(&output[output.length - s.bytes()]);
		return output;
	}
private:
	const BigInt q;
	const BigInt x;
	Fixed_Base_Power_Mod powermod_g_p;
	Modular_Reducer mod_q;
}

/**
* Object that can verify a DSA signature
*/
final class DSA_Verification_Operation : Verification
{
public:

	this(in DSA_PublicKey dsa) 
	{
		q = dsa.group_q();
		y = dsa.get_y();
		powermod_g_p = Fixed_Base_Power_Mod(dsa.group_g(), dsa.group_p());
		powermod_y_p = Fixed_Base_Power_Mod(y, dsa.group_p());
		mod_p = Modular_Reducer(dsa.group_p());
		mod_q = Modular_Reducer(dsa.group_q());
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return q.bytes(); }
	size_t max_input_bits() const { return q.bits(); }

	bool with_recovery() const { return false; }

	bool verify(in ubyte* msg, size_t msg_len,
	            in ubyte* sig, size_t sig_len)
	{
		import std.concurrency : spawn, receiveOnly, send, thisTid;
		const ref BigInt q = mod_q.get_modulus();
		
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
								thisTid, powermod_g_p, mod_q, s, i);
		
		BigInt s_r = powermod_y_p(mod_q.multiply(s, r));
		BigInt s_i = receiveOnly!BigInt();
		
		s = mod_p.multiply(s_i, s_r);
		
		return (mod_q.reduce(s) == r);
	}

private:
	const BigInt q;
	const BigInt y;

	Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
	Modular_Reducer mod_p, mod_q;
}