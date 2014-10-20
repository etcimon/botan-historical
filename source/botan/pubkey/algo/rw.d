/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rw;

import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.utils.parsing;
import std.algorithm;
import future;

/**
* Rabin-Williams Public Key
*/
class RW_PublicKey : IF_Scheme_PublicKey
{
public:
	string algo_name() const { return "RW"; }

	this(in AlgorithmIdentifier alg_id,
					 in SafeVector!ubyte key_bits)
	{
		super(alg_id, key_bits);
	}

	this(in BigInt mod, const ref BigInt exponent)
	{
		super(mod, exponent);
	}

package:
	this() {}
};

/**
* Rabin-Williams Private Key
*/
class RW_PrivateKey : RW_PublicKey,
					  IF_Scheme_PrivateKey
{
public:
	this(in AlgorithmIdentifier alg_id,
					  in SafeVector!ubyte key_bits,
					  RandomNumberGenerator rng) 
	{
		super(rng, alg_id, key_bits);
	}

	this(RandomNumberGenerator rng,
					  const ref BigInt p, const ref BigInt q,
					  const ref BigInt e, const ref BigInt d = 0,
					  const ref BigInt n = 0)
	{
		super(rng, p, q, e, d, n);
	}

	/*
	* Create a Rabin-Williams private key
	*/
	this(RandomNumberGenerator rng,
	     size_t bits, size_t exp = 2)
	{
		if (bits < 1024)
			throw new Invalid_Argument(algo_name() ~ ": Can't make a key that is only " ~
			                           std.conv.to!string(bits) ~ " bits long");
		if (exp < 2 || exp % 2 == 1)
			throw new Invalid_Argument(algo_name() ~ ": Invalid encryption exponent");
		
		e = exp;
		
		do
		{
			p = random_prime(rng, (bits + 1) / 2, e / 2, 3, 4);
			q = random_prime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
			n = p * q;
		} while(n.bits() != bits);
		
		d = inverse_mod(e, lcm(p - 1, q - 1) >> 1);
		d1 = d % (p - 1);
		d2 = d % (q - 1);
		c = inverse_mod(q, p);
		
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
		
		if ((e * d) % (lcm(p - 1, q - 1) / 2) != 1)
			return false;
		
		return signature_consistency_check(rng, *this, "EMSA2(SHA-1)");
	}
};

/**
* Rabin-Williams Signature Operation
*/
class RW_Signature_Operation : Signature
{
public:
	this(in RW_PrivateKey rw) 
	{
		n = rw.get_n();
		e = rw.get_e();
		q = rw.get_q();
		c = rw.get_c();
		powermod_d1_p = Fixed_Exponent_Power_Mod(rw.get_d1(), rw.get_p());
		powermod_d2_q = Fixed_Exponent_Power_Mod(rw.get_d2(), rw.get_q());
		mod_p = Fixed_Exponent_Power_Mod(rw.get_p());
	}

	size_t max_input_bits() const { return (n.bits() - 1); }

	SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
	                      RandomNumberGenerator rng)
	{
		rng.add_entropy(msg, msg_len);
		
		if (!blinder.initialized())
		{
			BigInt k = BigInt(rng, std.algorithm.min(160, n.bits() - 1));
			blinder = Blinder(power_mod(k, e, n), inverse_mod(k, n), n);
		}
		
		BigInt i = BigInt(msg, msg_len);
		
		if (i >= n || i % 16 != 12)
			throw new Invalid_Argument("Rabin-Williams: invalid input");
		
		if (jacobi(i, n) != 1)
			i >>= 1;
		
		i = blinder.blind(i);

		import std.concurrency : spawn, thisTid, send, receiveOnly;

		auto tid = spawn((Tid tid, Fixed_Exponent_Power_Mod powermod_d1_p2, BigInt i2) 
		                       { send(tid, powermod_d1_p2(i2)); }, thisTid, powermod_d1_p, i);
		const BigInt j2 = powermod_d2_q(i);
		BigInt j1 = receiveOnly!BigInt();
		
		j1 = mod_p.reduce(sub_mul(j1, j2, c));
		
		const BigInt r = blinder.unblind(mul_add(j1, q, j2));
		
		return BigInt.encode_1363(std.algorithm.min(r, n - r), n.bytes());
	}
private:
	const ref BigInt n;
	const ref BigInt e;
	const ref BigInt q;
	const ref BigInt c;

	Unique!Fixed_Exponent_Power_Mod powermod_d1_p, powermod_d2_q;
	Modular_Reducer mod_p;
	Blinder blinder;
};

/**
* Rabin-Williams Verification Operation
*/
class RW_Verification_Operation : Verification
{
public:
	this(in RW_PublicKey rw)
	{
		n = rw.get_n();
		powermod_e_n = Fixed_Exponent_Power_Mod(rw.get_e(), rw.get_n());
	}

	size_t max_input_bits() const { return (n.bits() - 1); }
	bool with_recovery() const { return true; }

	SafeVector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
	{
		BigInt m(msg, msg_len);
		
		if ((m > (n >> 1)) || m.is_negative())
			throw new Invalid_Argument("RW signature verification: m > n / 2 || m < 0");
		
		BigInt r = powermod_e_n(m);
		if (r % 16 == 12)
			return BigInt.encode_locked(r);
		if (r % 8 == 6)
			return BigInt.encode_locked(2*r);
		
		r = n - r;
		if (r % 16 == 12)
			return BigInt.encode_locked(r);
		if (r % 8 == 6)
			return BigInt.encode_locked(2*r);
		
		throw new Invalid_Argument("RW signature verification: Invalid signature");
	}

private:
	const ref BigInt n;
	Fixed_Exponent_Power_Mod powermod_e_n;
};
