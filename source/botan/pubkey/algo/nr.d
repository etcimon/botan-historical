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
import future;

/**
* Nyberg-Rueppel Public Key
*/
class NR_PublicKey : DL_Scheme_PublicKey
{
public:
	@property string algo_name() const { return "NR"; }

	DL_Group.Format group_format() const { return DL_Group.ANSI_X9_57; }

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return group_q().bytes(); }
	size_t max_input_bits() const { return (group_q().bits() - 1); }


	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits) 
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_57);
	}

	/*
	* NR_PublicKey Constructor
	*/
	this(in DL_Group grp, const ref BigInt y1)
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
final class NR_PrivateKey : NR_PublicKey,
					 DL_Scheme_PrivateKey
{
public:
	/*
* Check Private Nyberg-Rueppel Parameters
*/
	bool check_key(RandomNumberGenerator rng, bool strong) const
	{
		if (!super.check_key(rng, strong) || m_x >= group_q())
			return false;
		
		if (!strong)
			return true;
		
		return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
	}


	/*
	* Create a NR private key
	*/
	this(RandomNumberGenerator rng,
	     const ref DL_Group grp,
	     const ref BigInt x_arg)
	{
		m_group = grp;
		m_x = x_arg;
		
		if (m_x == 0)
			m_x = BigInt.random_integer(rng, 2, group_q() - 1);
		
		m_y = power_mod(group_g(), m_x, group_p());
		
		if (x_arg == 0)
			gen_check(rng);
		else
			load_check(rng);
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     RandomNumberGenerator rng)
	{ 
		super(alg_id, key_bits, DL_Group.ANSI_X9_57);
		m_y = power_mod(group_g(), m_x, group_p());
		
		load_check(rng);
	}

}

/**
* Nyberg-Rueppel signature operation
*/
final class NR_Signature_Operation : Signature
{
public:
	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_q.bytes(); }
	size_t max_input_bits() const { return (m_q.bits() - 1); }

	this(in NR_PrivateKey nr)
	{
		m_q = nr.group_q();
		m_x = nr.get_x();
		m_powermod_g_p = Fixed_Base_Power_Mod(nr.group_g(), nr.group_p());
		m_mod_q = Modular_Reducer(nr.group_q());
	}

	Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len,
	                      RandomNumberGenerator rng)
	{
		rng.add_entropy(msg, msg_len);
		
		BigInt f = BigInt(msg, msg_len);
		
		if (f >= m_q)
			throw new Invalid_Argument("NR_Signature_Operation: Input is out of range");
		
		BigInt c, d;
		
		while(c == 0)
		{
			BigInt k;
			do
				k.randomize(rng, m_q.bits());
			while(k >= m_q);
			
			c = m_mod_q.reduce(m_powermod_g_p(k) + f);
			d = m_mod_q.reduce(k - x * c);
		}
		
		Secure_Vector!ubyte output = Secure_Vector!ubyte(2*m_q.bytes());
		c.binary_encode(&output[output.length / 2 - c.bytes()]);
		d.binary_encode(&output[output.length - d.bytes()]);
		return output;
	}
private:
	const BigInt m_q;
	const BigInt m_x;
	Fixed_Base_Power_Mod m_powermod_g_p;
	Modular_Reducer m_mod_q;
}

/**
* Nyberg-Rueppel verification operation
*/
final class NR_Verification_Operation : Verification
{
public:
	this(in NR_PublicKey nr) 
	{
		m_q = nr.group_q();
		m_y = nr.get_y();
		m_powermod_g_p = Fixed_Base_Power_Mod(nr.group_g(), nr.group_p());
		m_powermod_y_p = Fixed_Base_Power_Mod(y, nr.group_p());
		m_mod_p = Modular_Reducer(nr.group_p());
		m_mod_q = Modular_Reducer(nr.group_q());
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_q.bytes(); }
	size_t max_input_bits() const { return (m_q.bits() - 1); }

	bool with_recovery() const { return true; }

	Secure_Vector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
	{
		const BigInt q = m_mod_q.get_modulus(); // todo: why not use m_q?
		size_t msg_len = msg.length;
		if (msg_len != 2*q.bytes())
			throw new Invalid_Argument("NR verification: Invalid signature");
		
		BigInt c = BigInt(msg, q.bytes());
		BigInt d = BigInt(msg + q.bytes(), q.bytes());
		
		if (c.is_zero() || c >= q || d >= q)
			throw new Invalid_Argument("NR verification: Invalid signature");
		import std.concurrency : spawn, receiveOnly, send, thisTid;

		auto tid = spawn((Tid tid, Fixed_Base_Power_Mod powermod_y_p2, BigInt c2) { send(tid, powermod_y_p2(c2)); }, thisTid, m_powermod_y_p, c );
		BigInt g_d = m_powermod_g_p(d);
		
		BigInt i = m_mod_p.multiply(g_d, receiveOnly!BigInt());
		return BigInt.encode_locked(m_mod_q.reduce(c - i));
	}
private:
	const BigInt m_q;
	const BigInt m_y;

	Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
	Modular_Reducer m_mod_p, m_mod_q;
}