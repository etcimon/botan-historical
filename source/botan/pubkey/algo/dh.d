/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dh;

import botan.constants;
static if (BOTAN_HAS_DIFFIE_HELLMAN):

import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;

/**
* This class represents Diffie-Hellman public keys.
*/
class DH_PublicKey : DL_Scheme_PublicKey
{
public:
	@property string algo_name() const { return "DH"; }

	/*
	* Return the public value for key agreement
	*/
	Vector!ubyte public_value() const
	{
		return unlock(BigInt.encode_1363(y, group_p().bytes()));
	}

	size_t max_input_bits() const { return group_p().bits(); }

	DL_Group.Format group_format() const { return DL_Group.ANSI_X9_42; }

	this(in Algorithm_Identifier alg_id,
					 in Secure_Vector!ubyte key_bits)
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_42);
	}

	/**
	* Construct a public key with the specified parameters.
	* @param grp the DL group to use in the key
	* @param y the public value y
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
* This class represents Diffie-Hellman private keys.
*/
class DH_PrivateKey : DH_PublicKey,
					  PK_Key_Agreement_Key,
					  DL_Scheme_PrivateKey
{
public:
	/*
	* Return the public value for key agreement
	*/
	Vector!ubyte public_value() const
	{
		return public_value();
	}

	/**
	* Load a DH private key
	* @param alg_id the algorithm id
	* @param key_bits the subject public key
	* @param rng a random number generator
	*/
	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     RandomNumberGenerator rng) 
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_42);
		if (m_y == 0)
			m_y = power_mod(group_g(), m_x, group_p());
		
		load_check(rng);
	}

	/**
	* Construct a private key with predetermined value.
	* @param rng random number generator to use
	* @param grp the group to be used in the key
	* @param x_args the key's secret value (or if zero, generate a new key)
	*/
	this(RandomNumberGenerator rng,
	     in DL_Group grp,
	     in BigInt x_arg = 0)
	{
		m_group = grp;
		m_x = x_arg;
		
		if (m_x == 0)
		{
			const BigInt m_p = group_p();
			m_x.randomize(rng, 2 * dl_work_factor(m_p.bits()));
		}
		
		if (m_y == 0)
			m_y = power_mod(group_g(), m_x, group_p());
		
		if (m_x == 0)
			gen_check(rng);
		else
			load_check(rng);
	}
}

/**
* DH operation
*/
class DH_KA_Operation : Key_Agreement
{
public:
	this(in DH_PrivateKey dh, RandomNumberGenerator rng) 
	{
		m_p = dh.group_p();
		m_powermod_x_p = Fixed_Exponent_Power_Mod(dh.get_x(), m_p);
		BigInt k = BigInt(rng, m_p.bits() - 1);
		m_blinder = Blinder(k, m_powermod_x_p(inverse_mod(k, m_p)), m_p);
	}

	Secure_Vector!ubyte agree(in ubyte* w, size_t w_len)
	{
		BigInt input = BigInt.decode(w, w_len);
		
		if (input <= 1 || input >= m_p - 1)
			throw new Invalid_Argument("DH agreement - invalid key provided");
		
		BigInt r = m_blinder.unblind(m_powermod_x_p(m_blinder.blind(input)));
		
		return BigInt.encode_1363(r, m_p.bytes());
	}

private:
	const BigInt m_p;

	Fixed_Exponent_Power_Mod m_powermod_x_p;
	Blinder m_blinder;
}