/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rsa;

import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import future;

/**
* RSA Public Key
*/
class RSA_PublicKey : IF_Scheme_PublicKey
{
public:
	string algo_name() const { return "RSA"; }

	this(in AlgorithmIdentifier alg_id,
		 in SafeVector!ubyte key_bits) 
	{
		super(alg_id, key_bits);
	}

	/**
	* Create a RSA_PublicKey
	* @arg n the modulus
	* @arg e the exponent
	*/
	this(in BigInt n, const ref BigInt e)
	{
		super(n, e);
	}

package:
	this() {}
};

/**
* RSA Private Key
*/
class RSA_PrivateKey : RSA_PublicKey,
					   IF_Scheme_PrivateKey
{
public:
	/*
	* Check Private RSA Parameters
	*/
	bool check_key(RandomNumberGenerator rng, bool strong) const
	{
		if (!super.check_key(rng, strong))
			return false;
		
		if (!strong)
			return true;
		
		if ((e * d) % lcm(p - 1, q - 1) != 1)
			return false;
		
		return signature_consistency_check(rng, this, "EMSA4(SHA-1)");
	}

	this(in AlgorithmIdentifier alg_id,
						in SafeVector!ubyte key_bits,
						RandomNumberGenerator rng) 
	{
		super(rng, alg_id, key_bits);
	}

	/**
	* Construct a private key from the specified parameters.
	* @param rng a random number generator
	* @param p the first prime
	* @param q the second prime
	* @param e the exponent
	* @param d if specified, this has to be d with
	* exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
	* the constructor to calculate it.
	* @param n if specified, this must be n = p * q. Leave it as 0
	* if you wish to the constructor to calculate it.
	*/
	this(RandomNumberGenerator rng,
						const ref BigInt p, const ref BigInt q,
						const ref BigInt e, const ref BigInt d = 0,
						const ref BigInt n = 0)
	{
		super(rng, p, q, e, d, n);
	}

	/**
	* Create a new private key with the specified bit length
	* @param rng the random number generator to use
	* @param bits the desired bit length of the private key
	* @param exp the public exponent to be used
	*/
	this(RandomNumberGenerator rng,
	     size_t bits, size_t exp = 65537)
	{
		if (bits < 1024)
			throw new Invalid_Argument(algo_name() ~ ": Can't make a key that is only " ~
			                           std.conv.to!string(bits) ~ " bits long");
		if (exp < 3 || exp % 2 == 0)
			throw new Invalid_Argument(algo_name() ~ ": Invalid encryption exponent");
		
		e = exp;
		
		do
		{
			p = random_prime(rng, (bits + 1) / 2, e);
			q = random_prime(rng, bits - p.bits(), e);
			n = p * q;
		} while(n.bits() != bits);
		
		d = inverse_mod(e, lcm(p - 1, q - 1));
		d1 = d % (p - 1);
		d2 = d % (q - 1);
		c = inverse_mod(q, p);
		
		gen_check(rng);
	}
};

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation : Signature,
							  public Decryption
{
public:
	this(in RSA_PrivateKey rsa,
	     RandomNumberGenerator rng) 
	{
		n = rsa.get_n();
		q = rsa.get_q();
		c = rsa.get_c();
		powermod_e_n = Fixed_Exponent_Power_Mod(rsa.get_e(), rsa.get_n());
		powermod_d1_p = Fixed_Exponent_Power_Mod(rsa.get_d1(), rsa.get_p());
		powermod_d2_q = Fixed_Exponent_Power_Mod(rsa.get_d2(), rsa.get_q());
		mod_p = rsa.get_p();
		BigInt k = BigInt(rng, n.bits() - 1);
		blinder = Blinder(powermod_e_n(k), inverse_mod(k, n), n);
	}

	size_t max_input_bits() const { return (n.bits() - 1); }

	SafeVector!ubyte
		sign(in ubyte* msg, size_t msg_len,
		     RandomNumberGenerator rng)
	{
		rng.add_entropy(msg, msg_len);
		
		/* We don't check signatures against powermod_e_n here because
			PK_Signer checks verification consistency for all signature
			algorithms.
		*/
		
		const BigInt m = BigInt(msg, msg_len);
		const BigInt x = blinder.unblind(private_op(blinder.blind(m)));
		return BigInt.encode_1363(x, n.bytes());
	}

	/*
	* RSA Decryption Operation
	*/
	SafeVector!ubyte decrypt(in ubyte* msg, size_t msg_len)
	{
		const BigInt m = BigInt(msg, msg_len);
		const BigInt x = blinder.unblind(private_op(blinder.blind(m)));
		
		BOTAN_ASSERT(m == powermod_e_n(x),
		             "RSA decrypt passed consistency check");
		
		return BigInt.encode_locked(x);
	}
private:
	BigInt private_op(in BigInt m) const
	{
		if (m >= n)
			throw new Invalid_Argument("RSA private op - input is too large");

		import std.concurrency : spawn, receiveOnly, thidTid, send;
		auto tid = spawn((Tid tid, Fixed_Exponent_Power_Mod powermod_d1_p2, BigInt m2) { send(tid, powermod_d1_p(m2)); }, thisTid, powermod_d1_p, m);
		BigInt j2 = powermod_d2_q(m);
		BigInt j1 = receiveOnly!BigInt();
		
		j1 = mod_p.reduce(sub_mul(j1, j2, c));
		
		return mul_add(j1, q, j2);
	}

	const ref BigInt n;
	const ref BigInt q;
	const ref BigInt c;
	Fixed_Exponent_Power_Mod powermod_e_n, powermod_d1_p, powermod_d2_q;
	Modular_Reducer mod_p;
	Blinder blinder;
};

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation : Verification,
							 Encryption
{
public:
	this(in RSA_PublicKey rsa)
	{
		n = rsa.get_n();
		powermod_e_n = Fixed_Exponent_Power_Mod(rsa.get_e(), rsa.get_n());
	}

	size_t max_input_bits() const { return (n.bits() - 1); }
	bool with_recovery() const { return true; }

	SafeVector!ubyte encrypt(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator)
	{
		BigInt m = BigInt(msg, msg_len);
		return BigInt.encode_1363(public_op(m), n.bytes());
	}

	SafeVector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
	{
		BigInt m = BigInt(msg, msg_len);
		return BigInt.encode_locked(public_op(m));
	}

private:
	BigInt public_op(in BigInt m) const
	{
		if (m >= n)
			throw new Invalid_Argument("RSA public op - input is too large");
		return powermod_e_n(m);
	}

	const ref BigInt n;
	Fixed_Exponent_Power_Mod powermod_e_n;
};