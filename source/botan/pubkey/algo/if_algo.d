/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.if_algo;

import botan.math.bigint.bigint;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IF_Scheme_PublicKey : Public_Key
{
public:

	this(in Algorithm_Identifier,
	     in Secure_Vector!ubyte key_bits)
	{
		BER_Decoder(key_bits)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode(n)
				.decode(e)
				.verify_end()
				.end_cons();
	}

	this(in BigInt _n, const ref BigInt _e)
	{
		n = _n;
		e = _e; 
	}

	/*
	* Check IF Scheme Private Parameters
	*/
	bool  check_key(RandomNumberGenerator rng,
	                bool strong) const
	{
		if (n < 35 || n.is_even() || e < 2 || d < 2 || p < 3 || q < 3 || p*q != n)
			return false;
		
		if (d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
			return false;
		
		const size_t prob = (strong) ? 56 : 12;
		
		if (!is_prime(p, rng, prob) || !is_prime(q, rng, prob))
			return false;
		return true;
	}

	Algorithm_Identifier algorithm_identifier() const
	{
		return Algorithm_Identifier(get_oid(),
		                           Algorithm_Identifier.USE_NULL_PARAM);
	}

	Vector!ubyte x509_subject_public_key() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(n)
				.encode(e)
				.end_cons()
				.get_contents_unlocked();
	}

	/**
	* @return public modulus
	*/
	const ref BigInt get_n() const { return n; }

	/**
	* @return public exponent
	*/
	const ref BigInt get_e() const { return e; }

	size_t max_input_bits() const { return (n.bits() - 1); }

	override size_t estimated_strength() const
	{
		return dl_work_factor(n.bits());
	}

protected:
	this() {}

	BigInt n, e;
};

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
final class IF_Scheme_PrivateKey : IF_Scheme_PublicKey,
							 Private_Key
{
public:
	this(RandomNumberGenerator rng,
	     const Algorithm_Identifier,
	     in Secure_Vector!ubyte key_bits)
	{
		BER_Decoder(key_bits)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check!size_t(0, "Unknown PKCS #1 key format version")
				.decode(n)
				.decode(e)
				.decode(d)
				.decode(p)
				.decode(q)
				.decode(d1)
				.decode(d2)
				.decode(c)
				.end_cons();
		
		load_check(rng);
	}

	this(RandomNumberGenerator rng,
	     const ref BigInt prime1,
	     const ref BigInt prime2,
	     const ref BigInt exp,
	     const ref BigInt d_exp,
	     const ref BigInt mod)
	{
		p = prime1;
		q = prime2;
		e = exp;
		d = d_exp;
		n = mod.is_nonzero() ? mod : p * q;
		
		if (d == 0)
		{
			BigInt inv_for_d = lcm(p - 1, q - 1);
			if (e.is_even())
				inv_for_d >>= 1;
			
			d = inverse_mod(e, inv_for_d);
		}
		
		d1 = d % (p - 1);
		d2 = d % (q - 1);
		c = inverse_mod(q, p);
		
		load_check(rng);
	}

	/*
	* Check IF Scheme Public Parameters
	*/
	bool check_key(RandomNumberGenerator, bool) const
	{
		if (n < 35 || n.is_even() || e < 2)
			return false;
		return true;
	}

	/**
	* Get the first prime p.
	* @return prime p
	*/
	const ref BigInt get_p() const { return p; }

	/**
	* Get the second prime q.
	* @return prime q
	*/
	const ref BigInt get_q() const { return q; }

	/**
	* Get d with exp * d = 1 mod (p - 1, q - 1).
	* @return d
	*/
	const ref BigInt get_d() const { return d; }

	const ref BigInt get_c() const { return c; }
	const ref BigInt get_d1() const { return d1; }
	const ref BigInt get_d2() const { return d2; }

	Secure_Vector!ubyte  pkcs8_Private_Key() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(cast(size_t)(0))
				.encode(n)
				.encode(e)
				.encode(d)
				.encode(p)
				.encode(q)
				.encode(d1)
				.encode(d2)
				.encode(c)
				.end_cons()
				.get_contents();
	}

protected:
	this() {}

	BigInt d, p, q, d1, d2, c;
};