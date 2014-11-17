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
				.decode(m_n)
				.decode(m_e)
				.verify_end()
				.end_cons();
	}

	this(in BigInt n, const ref BigInt e)
	{
		m_n = n;
		m_e = e; 
	}

	/*
	* Check IF Scheme Public Parameters
	*/
	bool check_key(RandomNumberGenerator, bool) const
	{
		if (m_n < 35 || m_n.is_even() || m_e < 2)
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
				.encode(m_n)
				.encode(m_e)
				.end_cons()
				.get_contents_unlocked();
	}

	/**
	* @return public modulus
	*/
	const BigInt get_n() const { return m_n; }

	/**
	* @return public exponent
	*/
	const BigInt get_e() const { return m_e; }

	size_t max_input_bits() const { return (m_n.bits() - 1); }

	override size_t estimated_strength() const
	{
		return dl_work_factor(m_n.bits());
	}

protected:
	this() {}

	BigInt m_n, m_e;
}

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
final class IF_Scheme_PrivateKey : IF_Scheme_PublicKey,
							 Private_Key
{
public:
	this(RandomNumberGenerator rng, in Algorithm_Identifier, in Secure_Vector!ubyte key_bits)
	{
		BER_Decoder(key_bits)
				.start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check!size_t(0, "Unknown PKCS #1 key format version")
				.decode(m_n)
				.decode(m_e)
				.decode(m_d)
				.decode(m_p)
				.decode(m_q)
				.decode(m_d1)
				.decode(m_d2)
				.decode(m_c)
				.end_cons();
		
		load_check(rng);
	}

	this(RandomNumberGenerator rng,
	     in BigInt prime1,
	     in BigInt prime2,
	     in BigInt exp,
	     in BigInt d_exp,
	     in BigInt mod)
	{
		m_p = prime1;
		m_q = prime2;
		e = exp;
		m_d = d_exp;
		n = mod.is_nonzero() ? mod : m_p * m_q;
		
		if (m_d == 0)
		{
			BigInt inv_for_d = lcm(m_p - 1, m_q - 1);
			if (e.is_even())
				inv_for_d >>= 1;
			
			m_d = inverse_mod(e, inv_for_d);
		}
		
		m_d1 = m_d % (m_p - 1);
		m_d2 = m_d % (m_q - 1);
		m_c = inverse_mod(m_q, m_p);

		load_check(rng);

	}

	/*
	* Check IF Scheme Private Parameters
	*/
	bool  check_key(RandomNumberGenerator rng, bool strong) const
	{
		if (m_n < 35 || m_n.is_even() || m_e < 2 || m_d < 2 || m_p < 3 || m_q < 3 || m_p*m_q != m_n)
			return false;
		
		if (m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverse_mod(m_q, m_p))
			return false;
		
		const size_t prob = (strong) ? 56 : 12;
		
		if (!is_prime(m_p, rng, prob) || !is_prime(m_q, rng, prob))
			return false;
		return true;
	}

	/**
	* Get the first prime p.
	* @return prime p
	*/
	const BigInt get_p() const { return m_p; }

	/**
	* Get the second prime q.
	* @return prime q
	*/
	const BigInt get_q() const { return m_q; }

	/**
	* Get d with exp * d = 1 mod (p - 1, q - 1).
	* @return d
	*/
	const BigInt get_d() const { return m_d; }

	const BigInt get_c() const { return m_c; }
	const BigInt get_d1() const { return m_d1; }
	const BigInt get_d2() const { return m_d2; }

	Secure_Vector!ubyte  pkcs8_private_key() const
	{
		return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(cast(size_t)(0))
				.encode(m_n)
				.encode(m_e)
				.encode(m_d)
				.encode(m_p)
				.encode(m_q)
				.encode(m_d1)
				.encode(m_d2)
				.encode(m_c)
				.end_cons()
				.get_contents();
	}

protected:
	this() {}

	BigInt m_d, m_p, m_q, m_d1, m_d2, m_c;
}