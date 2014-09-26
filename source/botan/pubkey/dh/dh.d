/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dh.h>
#include <botan/numthry.h>
#include <botan/workfactor.h>
/*
* DH_PublicKey Constructor
*/
DH_PublicKey::DH_PublicKey(in DL_Group grp, const BigInt& y1)
{
	group = grp;
	y = y1;
}

/*
* Return the public value for key agreement
*/
Vector!( byte ) DH_PublicKey::public_value() const
{
	return unlock(BigInt::encode_1363(y, group_p().bytes()));
}

/*
* Create a DH private key
*/
DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng,
									  const DL_Group& grp,
									  const BigInt& x_arg)
{
	group = grp;
	x = x_arg;

	if(x == 0)
	{
		const BigInt& p = group_p();
		x.randomize(rng, 2 * dl_work_factor(p.bits()));
	}

	if(y == 0)
		y = power_mod(group_g(), x, group_p());

	if(x == 0)
		gen_check(rng);
	else
		load_check(rng);
}

/*
* Load a DH private key
*/
DH_PrivateKey::DH_PrivateKey(in AlgorithmIdentifier alg_id,
									  in SafeVector!byte key_bits,
									  RandomNumberGenerator& rng) :
	DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
{
	if(y == 0)
		y = power_mod(group_g(), x, group_p());

	load_check(rng);
}

/*
* Return the public value for key agreement
*/
Vector!( byte ) DH_PrivateKey::public_value() const
{
	return DH_PublicKey::public_value();
}

DH_KA_Operation::DH_KA_Operation(in DH_PrivateKey dh,
											RandomNumberGenerator& rng) :
	p(dh.group_p()), powermod_x_p(dh.get_x(), p)
{
	BigInt k(rng, p.bits() - 1);
	blinder = Blinder(k, powermod_x_p(inverse_mod(k, p)), p);
}

SafeVector!byte DH_KA_Operation::agree(in byte* w, size_t w_len)
{
	BigInt input = BigInt::decode(w, w_len);

	if(input <= 1 || input >= p - 1)
		throw new Invalid_Argument("DH agreement - invalid key provided");

	BigInt r = blinder.unblind(powermod_x_p(blinder.blind(input)));

	return BigInt::encode_1363(r, p.bytes());
}

}
