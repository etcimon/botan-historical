/*
* Discrete Logarithm Parameters
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.dl_group;
import botan.libstate.libstate;
import botan.parsing;
import botan.numthry;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.pipe;
import botan.codec.pem.pem;
import botan.workfactor;
/*
* DL_Group Constructor
*/
DL_Group::DL_Group()
{
	initialized = false;
}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(in string name)
{
	string pem = PEM_for_named_group(name);

	if (!pem)
		throw new Invalid_Argument("DL_Group: Unknown group " ~ name);

	PEM_decode(pem);
}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator rng,
						 PrimeType type, size_t pbits, size_t qbits)
{
	if (pbits < 512)
		throw new Invalid_Argument("DL_Group: prime size " ~ std.conv.to!string(pbits) +
									  " is too small");

	if (type == Strong)
	{
		p = random_safe_prime(rng, pbits);
		q = (p - 1) / 2;
		g = 2;
	}
	else if (type == Prime_Subgroup)
	{
		if (!qbits)
			qbits = 2 * dl_work_factor(pbits);

		q = random_prime(rng, qbits);
		BigInt X;
		while(p.bits() != pbits || !is_prime(p, rng))
		{
			X.randomize(rng, pbits);
			p = X - (X % (2*q) - 1);
		}

		g = make_dsa_generator(p, q);
	}
	else if (type == DSA_Kosherizer)
	{
		qbits = qbits ? qbits : ((pbits <= 1024) ? 160 : 256);

		generate_dsa_primes(rng,
								  global_state().algorithm_factory(),
								  p, q,
								  pbits, qbits);

		g = make_dsa_generator(p, q);
	}

	initialized = true;
}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator rng,
						 in Vector!ubyte seed,
						 size_t pbits, size_t qbits)
{
	if (!generate_dsa_primes(rng,
									global_state().algorithm_factory(),
									p, q, pbits, qbits, seed))
		throw new Invalid_Argument("DL_Group: The seed given does not "
									  "generate a DSA group");

	g = make_dsa_generator(p, q);

	initialized = true;
}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(in BigInt p1, ref const BigInt g1)
{
	initialize(p1, 0, g1);
}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(in BigInt p1, ref const BigInt q1, ref const BigInt g1)
{
	initialize(p1, q1, g1);
}

/*
* DL_Group Initializer
*/
void DL_Group::initialize(in BigInt p1, ref const BigInt q1, ref const BigInt g1)
{
	if (p1 < 3)
		throw new Invalid_Argument("DL_Group: Prime invalid");
	if (g1 < 2 || g1 >= p1)
		throw new Invalid_Argument("DL_Group: Generator invalid");
	if (q1 < 0 || q1 >= p1)
		throw new Invalid_Argument("DL_Group: Subgroup invalid");

	p = p1;
	g = g1;
	q = q1;

	initialized = true;
}

/*
* Verify that the group has been set
*/
void DL_Group::init_check() const
{
	if (!initialized)
		throw new Invalid_State("DLP group cannot be used uninitialized");
}

/*
* Verify the parameters
*/
bool DL_Group::verify_group(RandomNumberGenerator rng,
									 bool strong) const
{
	init_check();

	if (g < 2 || p < 3 || q < 0)
		return false;
	if ((q != 0) && ((p - 1) % q != 0))
		return false;

	const size_t prob = (strong) ? 56 : 10;

	if (!is_prime(p, rng, prob))
		return false;
	if ((q > 0) && !is_prime(q, rng, prob))
		return false;
	return true;
}

/*
* Return the prime
*/
ref const BigInt DL_Group::get_p() const
{
	init_check();
	return p;
}

/*
* Return the generator
*/
ref const BigInt DL_Group::get_g() const
{
	init_check();
	return g;
}

/*
* Return the subgroup
*/
ref const BigInt DL_Group::get_q() const
{
	init_check();
	if (q == 0)
		throw new Invalid_State("DLP group has no q prime specified");
	return q;
}

/*
* DER encode the parameters
*/
Vector!ubyte DL_Group::DER_encode(Format format) const
{
	init_check();

	if ((q == 0) && (format != PKCS_3))
		throw new Encoding_Error("The ANSI DL parameter formats require a subgroup");

	if (format == ANSI_X9_57)
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(p)
				.encode(q)
				.encode(g)
			.end_cons()
		.get_contents_unlocked();
	}
	else if (format == ANSI_X9_42)
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(p)
				.encode(g)
				.encode(q)
			.end_cons()
		.get_contents_unlocked();
	}
	else if (format == PKCS_3)
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(p)
				.encode(g)
			.end_cons()
		.get_contents_unlocked();
	}

	throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));
}

/*
* PEM encode the parameters
*/
string DL_Group::PEM_encode(Format format) const
{
	const Vector!ubyte encoding = DER_encode(format);

	if (format == PKCS_3)
		return pem.encode(encoding, "DH PARAMETERS");
	else if (format == ANSI_X9_57)
		return pem.encode(encoding, "DSA PARAMETERS");
	else if (format == ANSI_X9_42)
		return pem.encode(encoding, "X942 DH PARAMETERS");
	else
		throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));
}

/*
* Decode BER encoded parameters
*/
void DL_Group::BER_decode(in Vector!ubyte data,
								  Format format)
{
	BigInt new_p, new_q, new_g;

	BER_Decoder decoder(data);
	BER_Decoder ber = decoder.start_cons(ASN1_Tag.SEQUENCE);

	if (format == ANSI_X9_57)
	{
		ber.decode(new_p)
			.decode(new_q)
			.decode(new_g)
			.verify_end();
	}
	else if (format == ANSI_X9_42)
	{
		ber.decode(new_p)
			.decode(new_g)
			.decode(new_q)
			.discard_remaining();
	}
	else if (format == PKCS_3)
	{
		ber.decode(new_p)
			.decode(new_g)
			.discard_remaining();
	}
	else
		throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));

	initialize(new_p, new_q, new_g);
}

/*
* Decode PEM encoded parameters
*/
void DL_Group::PEM_decode(in string pem)
{
	string label;

	auto ber = unlock(pem.decode(pem, label));

	if (label == "DH PARAMETERS")
		BER_decode(ber, PKCS_3);
	else if (label == "DSA PARAMETERS")
		BER_decode(ber, ANSI_X9_57);
	else if (label == "X942 DH PARAMETERS")
		BER_decode(ber, ANSI_X9_42);
	else
		throw new Decoding_Error("DL_Group: Invalid PEM label " ~ label);
}

/*
* Create generator of the q-sized subgroup (DSA style generator)
*/
BigInt DL_Group::make_dsa_generator(in BigInt p, ref const BigInt q)
{
	const BigInt e = (p - 1) / q;

	if (e == 0 || (p - 1) % q > 0)
		throw new Invalid_Argument("make_dsa_generator q does not divide p-1");

	for (size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
	{
		BigInt g = power_mod(PRIMES[i], e, p);
		if (g > 1)
			return g;
	}

	throw new Internal_Error("DL_Group: Couldn't create a suitable generator");
}

}
