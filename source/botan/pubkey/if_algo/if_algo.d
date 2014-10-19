/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.if_algo;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
size_t IF_Scheme_PublicKey::estimated_strength() const
{
	return dl_work_factor(n.bits());
}

AlgorithmIdentifier IF_Scheme_PublicKey::algorithm_identifier() const
{
	return AlgorithmIdentifier(get_oid(),
										AlgorithmIdentifier.Encoding_Option.USE_NULL_PARAM);
}

Vector!ubyte IF_Scheme_PublicKey::x509_subject_public_key() const
{
	return DER_Encoder()
		.start_cons(ASN1_Tag.SEQUENCE)
			.encode(n)
			.encode(e)
		.end_cons()
		.get_contents_unlocked();
}

IF_Scheme_PublicKey::IF_Scheme_PublicKey(in AlgorithmIdentifier,
													  in SafeVector!ubyte key_bits)
{
	BER_Decoder(key_bits)
		.start_cons(ASN1_Tag.SEQUENCE)
		  .decode(n)
		  .decode(e)
		.verify_end()
		.end_cons();
}

/*
* Check IF Scheme Public Parameters
*/
bool IF_Scheme_PublicKey::check_key(RandomNumberGenerator, bool) const
{
	if (n < 35 || n.is_even() || e < 2)
		return false;
	return true;
}

SafeVector!ubyte IF_Scheme_PrivateKey::pkcs8_Private_Key() const
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

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator rng,
														 const AlgorithmIdentifier,
														 in SafeVector!ubyte key_bits)
{
	BER_Decoder(key_bits)
		.start_cons(ASN1_Tag.SEQUENCE)
			.decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
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

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator rng,
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
* Check IF Scheme Private Parameters
*/
bool IF_Scheme_PrivateKey::check_key(RandomNumberGenerator rng,
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

}
