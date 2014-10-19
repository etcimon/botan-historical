/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.nr;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import future;
NR_PublicKey::NR_PublicKey(in AlgorithmIdentifier alg_id,
									in SafeVector!ubyte key_bits) :
	DL_Scheme_PublicKey(alg_id, key_bits, DL_Group.ANSI_X9_57)
{
}

/*
* NR_PublicKey Constructor
*/
NR_PublicKey::NR_PublicKey(in DL_Group grp, const ref BigInt y1)
{
	group = grp;
	y = y1;
}

/*
* Create a NR private key
*/
NR_PrivateKey::NR_PrivateKey(RandomNumberGenerator rng,
									  const ref DL_Group grp,
									  const ref BigInt x_arg)
{
	group = grp;
	x = x_arg;

	if (x == 0)
		x = BigInt.random_integer(rng, 2, group_q() - 1);

	y = power_mod(group_g(), x, group_p());

	if (x_arg == 0)
		gen_check(rng);
	else
		load_check(rng);
}

NR_PrivateKey::NR_PrivateKey(in AlgorithmIdentifier alg_id,
									  in SafeVector!ubyte key_bits,
									  RandomNumberGenerator rng) :
	DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group.ANSI_X9_57)
{
	y = power_mod(group_g(), x, group_p());

	load_check(rng);
}

/*
* Check Private Nyberg-Rueppel Parameters
*/
bool NR_PrivateKey::check_key(RandomNumberGenerator rng, bool strong) const
{
	if (!DL_Scheme_PrivateKey::check_key(rng, strong) || x >= group_q())
		return false;

	if (!strong)
		return true;

	return signature_consistency_check(rng, *this, "EMSA1(SHA-1)");
}

NR_Signature_Operation::NR_Signature_Operation(in NR_PrivateKey nr) :
	q(nr.group_q()),
	x(nr.get_x()),
	powermod_g_p(nr.group_g(), nr.group_p()),
	mod_q(nr.group_q())
{
}

SafeVector!ubyte
NR_Signature_Operation::sign(in ubyte* msg, size_t msg_len,
									  RandomNumberGenerator rng)
{
	rng.add_entropy(msg, msg_len);

	BigInt f(msg, msg_len);

	if (f >= q)
		throw new Invalid_Argument("NR_Signature_Operation: Input is out of range");

	BigInt c, d;

	while(c == 0)
	{
		BigInt k;
		do
			k.randomize(rng, q.bits());
		while(k >= q);

		c = mod_q.reduce(powermod_g_p(k) + f);
		d = mod_q.reduce(k - x * c);
	}

	SafeVector!ubyte output = SafeVector!ubyte(2*q.bytes());
	c.binary_encode(&output[output.length / 2 - c.bytes()]);
	d.binary_encode(&output[output.length - d.bytes()]);
	return output;
}

NR_Verification_Operation::NR_Verification_Operation(in NR_PublicKey nr) :
	q(nr.group_q()), y(nr.get_y())
{
	powermod_g_p = Fixed_Base_Power_Mod(nr.group_g(), nr.group_p());
	powermod_y_p = Fixed_Base_Power_Mod(y, nr.group_p());
	mod_p = Modular_Reducer(nr.group_p());
	mod_q = Modular_Reducer(nr.group_q());
}

SafeVector!ubyte
NR_Verification_Operation::verify_mr(in ubyte* msg, size_t msg_len)
{
	const ref BigInt q = mod_q.get_modulus();
	size_t msg_len = msg.length;
	if (msg_len != 2*q.bytes())
		throw new Invalid_Argument("NR verification: Invalid signature");

	BigInt c(msg, q.bytes());
	BigInt d(msg + q.bytes(), q.bytes());

	if (c.is_zero() || c >= q || d >= q)
		throw new Invalid_Argument("NR verification: Invalid signature");

	auto future_y_c = std::async(std::launch::async, powermod_y_p, c);
	BigInt g_d = powermod_g_p(d);

	BigInt i = mod_p.multiply(g_d, future_y_c.get());
	return BigInt.encode_locked(mod_q.reduce(c - i));
}

}
