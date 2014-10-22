/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dh;

import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;

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

	this(in AlgorithmIdentifier alg_id,
					 in SafeVector!ubyte key_bits)
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_42);
	}

	/**
	* Construct a public key with the specified parameters.
	* @param grp the DL group to use in the key
	* @param y the public value y
	*/
	this(in DL_Group grp, const ref BigInt y1)
	{
		group = grp;
		y = y1;
	}
package:
	this() {}
};

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
	this(in AlgorithmIdentifier alg_id,
	     in SafeVector!ubyte key_bits,
	     RandomNumberGenerator rng) 
	{
		super(alg_id, key_bits, DL_Group.ANSI_X9_42);
		if (y == 0)
			y = power_mod(group_g(), x, group_p());
		
		load_check(rng);
	}

	/**
	* Construct a private key with predetermined value.
	* @param rng random number generator to use
	* @param grp the group to be used in the key
	* @param x_args the key's secret value (or if zero, generate a new key)
	*/
	this(RandomNumberGenerator rng,
	     const ref DL_Group grp,
	     const ref BigInt x_arg = 0)
	{
		group = grp;
		x = x_arg;
		
		if (x == 0)
		{
			const ref BigInt p = group_p();
			x.randomize(rng, 2 * dl_work_factor(p.bits()));
		}
		
		if (y == 0)
			y = power_mod(group_g(), x, group_p());
		
		if (x == 0)
			gen_check(rng);
		else
			load_check(rng);
	}
};

/**
* DH operation
*/
class DH_KA_Operation : Key_Agreement
{
public:
	this(in DH_PrivateKey dh,
	     RandomNumberGenerator rng) 
	{
		p = dh.group_p();
		powermod_x_p = Fixed_Exponent_Power_Mod(dh.get_x(), p);
		BigInt k = BigInt(rng, p.bits() - 1);
		blinder = Blinder(k, powermod_x_p(inverse_mod(k, p)), p);
	}

	SafeVector!ubyte agree(in ubyte* w, size_t w_len)
	{
		BigInt input = BigInt.decode(w, w_len);
		
		if (input <= 1 || input >= p - 1)
			throw new Invalid_Argument("DH agreement - invalid key provided");
		
		BigInt r = blinder.unblind(powermod_x_p(blinder.blind(input)));
		
		return BigInt.encode_1363(r, p.bytes());
	}

private:
	const ref BigInt p;

	Fixed_Exponent_Power_Mod powermod_x_p;
	Blinder blinder;
};