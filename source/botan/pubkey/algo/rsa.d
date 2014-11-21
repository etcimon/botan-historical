/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rsa;

import botan.constants;
static if (BOTAN_HAS_RSA):

import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import future;

/**
* RSA Public Key
*/
class RSA_PublicKey : IF_Scheme_PublicKey
{
public:
	@property string algo_name() const { return "RSA"; }

	this(in Algorithm_Identifier alg_id,
		 in Secure_Vector!ubyte key_bits) 
	{
		super(alg_id, key_bits);
	}

	/**
	* Create a RSA_PublicKey
	* @arg n the modulus
	* @arg e the exponent
	*/
	this(in BigInt n, in BigInt e)
	{
		super(n, e);
	}

protected:
	this() {}
}

/**
* RSA Private Key
*/
final class RSA_PrivateKey : RSA_PublicKey,
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
		
		if ((m_e * m_d) % lcm(m_p - 1, m_q - 1) != 1)
			return false;
		
		return signature_consistency_check(rng, this, "EMSA4(SHA-1)");
	}

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits, RandomNumberGenerator rng) 
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
	this(RandomNumberGenerator rng, in BigInt p, in BigInt q, in BigInt e, in BigInt d = 0, in BigInt n = 0)
	{
		super(rng, p, q, e, d, n);
	}

	/**
	* Create a new private key with the specified bit length
	* @param rng the random number generator to use
	* @param bits the desired bit length of the private key
	* @param exp the public exponent to be used
	*/
	this(RandomNumberGenerator rng, size_t bits, size_t exp = 65537)
	{
		if (bits < 1024)
			throw new Invalid_Argument(algo_name ~ ": Can't make a key that is only " ~ to!string(bits) ~ " bits long");
		if (exp < 3 || exp % 2 == 0)
			throw new Invalid_Argument(algo_name ~ ": Invalid encryption exponent");
		
		m_e = exp;
		
		do
		{
			m_p = random_prime(rng, (bits + 1) / 2, m_e);
			m_q = random_prime(rng, bits - m_p.bits(), m_e);
			m_n = m_p * m_q;
		} while (m_n.bits() != bits);
		
		m_d = inverse_mod(e, lcm(m_p - 1, m_q - 1));
		m_d1 = m_d % (m_p - 1);
		m_d2 = m_d % (m_q - 1);
		m_c = inverse_mod(m_q, m_p);
		
		gen_check(rng);
	}
}

/**
* RSA private (decrypt/sign) operation
*/
final class RSA_Private_Operation : Signature,
							  		Decryption
{
public:
	this(in RSA_PrivateKey rsa, RandomNumberGenerator rng) 
	{
		m_n = rsa.get_n();
		m_q = rsa.get_q();
		m_c = rsa.get_c();
		m_powermod_e_n = Fixed_Exponent_Power_Mod(rsa.get_e(), rsa.get_n());
		m_powermod_d1_p = Fixed_Exponent_Power_Mod(rsa.get_d1(), rsa.get_p());
		m_powermod_d2_q = Fixed_Exponent_Power_Mod(rsa.get_d2(), rsa.get_q());
		m_mod_p = rsa.get_p();
		BigInt k = BigInt(rng, m_n.bits() - 1);
		m_blinder = Blinder(m_powermod_e_n(k), inverse_mod(k, m_n), m_n);
	}

	size_t max_input_bits() const { return (n.bits() - 1); }

	Secure_Vector!ubyte
		sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng)
	{
		rng.add_entropy(msg, msg_len);
		
		/* We don't check signatures against powermod_e_n here because
			PK_Signer checks verification consistency for all signature
			algorithms.
		*/
		
		const BigInt m = BigInt(msg, msg_len);
		const BigInt x = m_blinder.unblind(private_op(m_blinder.blind(m)));
		return BigInt.encode_1363(x, n.bytes());
	}

	/*
	* RSA Decryption Operation
	*/
	Secure_Vector!ubyte decrypt(in ubyte* msg, size_t msg_len)
	{
		const BigInt m = BigInt(msg, msg_len);
		const BigInt x = m_blinder.unblind(private_op(m_blinder.blind(m)));
		
		assert(m == m_powermod_e_n(x), "RSA decrypt passed consistency check");
		
		return BigInt.encode_locked(x);
	}
private:
	BigInt private_op(in BigInt m) const
	{
		if (m >= m_n)
			throw new Invalid_Argument("RSA private op - input is too large");

		import std.concurrency : spawn, receiveOnly, thidTid, send;
		auto tid = spawn((Tid tid, Fixed_Exponent_Power_Mod powermod_d1_p2, BigInt m2) { send(tid, powermod_d1_p2(m2)); }, 
							thisTid, m_powermod_d1_p, m);
		BigInt j2 = m_powermod_d2_q(m);
		BigInt j1 = receiveOnly!BigInt();
		
		j1 = m_mod_p.reduce(sub_mul(j1, j2, c));
		
		return mul_add(j1, q, j2);
	}

	const BigInt m_n;
	const BigInt m_q;
	const BigInt m_c;
	Fixed_Exponent_Power_Mod m_powermod_e_n, m_powermod_d1_p, m_powermod_d2_q;
	Modular_Reducer m_mod_p;
	Blinder m_blinder;
}

/**
* RSA public (encrypt/verify) operation
*/
final class RSA_Public_Operation : Verification,
								   Encryption
{
public:
	this(in RSA_PublicKey rsa)
	{
		m_n = rsa.get_n();
		m_powermod_e_n = Fixed_Exponent_Power_Mod(rsa.get_e(), rsa.get_n());
	}

	size_t max_input_bits() const { return (n.bits() - 1); }
	bool with_recovery() const { return true; }

	Secure_Vector!ubyte encrypt(in ubyte* msg, size_t msg_len, RandomNumberGenerator)
	{
		BigInt m = BigInt(msg, msg_len);
		return BigInt.encode_1363(public_op(m), m_n.bytes());
	}

	Secure_Vector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
	{
		BigInt m = BigInt(msg, msg_len);
		return BigInt.encode_locked(public_op(m));
	}

private:
	BigInt public_op(in BigInt m) const
	{
		if (m >= m_n)
			throw new Invalid_Argument("RSA public op - input is too large");
		return m_powermod_e_n(m);
	}

	const BigInt n;
	Fixed_Exponent_Power_Mod m_powermod_e_n;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import core.atomic;

__gshared size_t total_tests;


size_t rsaes_kat(string e,
                 string p,
                 string q,
                 string msg,
                 string padding,
                 string nonce,
                 string output)
{
	atomicOp!"+="(total_tests, 1);
	AutoSeeded_RNG rng;
	
	auto privkey = scoped!RSA_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
	
	auto pubkey = scoped!RSA_PublicKey(privkey);
	
	if (padding == "")
		padding = "Raw";
	
	auto enc = scoped!PK_Encryptor_EME(pubkey, padding);
	auto dec = scoped!PK_Decryptor_EME(privkey, padding);
	
	return validate_encryption(enc, dec, "RSAES/" ~ padding, msg, nonce, output);
}

size_t rsa_sig_kat(string e,
                   string p,
                   string q,
                   string msg,
                   string padding,
                   string nonce,
                   string output)
{
	atomicOp!"+="(total_tests, 1);
	AutoSeeded_RNG rng;
	
	auto privkey = scoped!RSA_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
	
	auto pubkey = scoped!RSA_PublicKey(privkey);
	
	if (padding == "")
		padding = "Raw";
	
	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);
	
	return validate_signature(verify, sign, "RSA/" ~ padding, msg, rng, nonce, output);
}

size_t rsa_sig_verify(string e,
                      string n,
                      string msg,
                      string padding,
                      string signature)
{
	atomicOp!"+="(total_tests, 1);
	AutoSeeded_RNG rng;
	
	BigInt e_bn = BigInt(e);
	BigInt n_bn = BigInt(n);
	
	auto key = scoped!RSA_PublicKey(n_bn, e_bn);
	
	if (padding == "")
		padding = "Raw";
	
	PK_Verifier verify = PK_Verifier(key, padding);
	
	if (!verify.verify_message(hex_decode(msg), hex_decode(signature)))
		return 1;
	return 0;
}

size_t test_pk_keygen(RandomNumberGenerator rng)
{

	auto rsa1024 = scoped!RSA_PrivateKey(rng, 1024);
	rsa1024.check_key(rng, true);
	atomicOp!"+="(total_tests, 1);
	fails += validate_save_and_load(&rsa1024, rng);
	
	auto rsa2048 = scoped!RSA_PrivateKey(rng, 2048);
	rsa2048.check_key(rng, true);
	atomicOp!"+="(total_tests, 1);
	fails += validate_save_and_load(&rsa2048, rng);

}

unittest
{
	size_t fails = 0;
	
	AutoSeeded_RNG rng;

	
	File rsa_enc = File("test_data/pubkey/rsaes.vec", "r");
	File rsa_sig = File("test_data/pubkey/rsa_sig.vec", "r");
	File rsa_verify = File("test_data/pubkey/rsa_verify.vec", "r");
	
	
	fails += run_tests_bb(rsa_enc, "RSA Encryption", "Ciphertext", true,
	                      (string[string] m)
	                      {
		return rsaes_kat(m["E"], m["P"], m["Q"], m["Msg"],
		m["Padding"], m["Nonce"], m["Ciphertext"]);
	});
	
	fails += run_tests_bb(rsa_sig, "RSA Signature", "Signature", true,
	                      (string[string] m)
	                      {
		return rsa_sig_kat(m["E"], m["P"], m["Q"], m["Msg"],
		m["Padding"], m["Nonce"], m["Signature"]);
	});
	
	fails += run_tests_bb(rsa_verify, "RSA Verify", "Signature", true,
	                      (string[string] m)
	                      {
		return rsa_sig_verify(m["E"], m["N"], m["Msg"],
		m["Padding"], m["Signature"]);
	});
	
	test_report("rsa", total_tests, fails);
}