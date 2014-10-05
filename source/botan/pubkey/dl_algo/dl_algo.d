/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.dl_algo;
import botan.numthry;
import botan.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
size_t DL_Scheme_PublicKey::estimated_strength() const
{
	return dl_work_factor(group.get_p().bits());
}

AlgorithmIdentifier DL_Scheme_PublicKey::algorithm_identifier() const
{
	return AlgorithmIdentifier(get_oid(),
										group.DER_encode(group_format()));
}

Vector!ubyte DL_Scheme_PublicKey::x509_subject_public_key() const
{
	return DER_Encoder().encode(y).get_contents_unlocked();
}

DL_Scheme_PublicKey::DL_Scheme_PublicKey(in AlgorithmIdentifier alg_id,
													  in SafeVector!ubyte key_bits,
													  DL_Group::Format format)
{
	group.BER_decode(alg_id.parameters, format);

	BER_Decoder(key_bits).decode(y);
}

SafeVector!ubyte DL_Scheme_PrivateKey::pkcs8_Private_Key() const
{
	return DER_Encoder().encode(x).get_contents();
}

DL_Scheme_PrivateKey::DL_Scheme_PrivateKey(in AlgorithmIdentifier alg_id,
														 in SafeVector!ubyte key_bits,
														 DL_Group::Format format)
{
	group.BER_decode(alg_id.parameters, format);

	BER_Decoder(key_bits).decode(x);
}

/*
* Check Public DL Parameters
*/
bool DL_Scheme_PublicKey::check_key(RandomNumberGenerator rng,
												bool strong) const
{
	if (y < 2 || y >= group_p())
		return false;
	if (!group.verify_group(rng, strong))
		return false;
	return true;
}

/*
* Check DL Scheme Private Parameters
*/
bool DL_Scheme_PrivateKey::check_key(RandomNumberGenerator rng,
												 bool strong) const
{
	ref const BigInt p = group_p();
	ref const BigInt g = group_g();

	if (y < 2 || y >= p || x < 2 || x >= p)
		return false;
	if (!group.verify_group(rng, strong))
		return false;

	if (!strong)
		return true;

	if (y != power_mod(g, x, p))
		return false;

	return true;
}

}
