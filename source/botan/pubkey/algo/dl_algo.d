/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dl_algo;

import botan.pubkey.algo.dl_group;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* This class represents discrete logarithm (DL) public keys.
*/
class DL_Scheme_PublicKey : Public_Key
{
public:
	bool check_key(RandomNumberGenerator rng,
	               bool strong) const
	{
		const ref BigInt p = group_p();
		const ref BigInt g = group_g();
		
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

	Algorithm_Identifier algorithm_identifier() const
	{
		return Algorithm_Identifier(get_oid(),
		                           group.DER_encode(group_format()));
	}

	Vector!ubyte x509_subject_public_key() const
	{
		return DER_Encoder().encode(y).get_contents_unlocked();
	}

	/**
	* Get the DL domain parameters of this key.
	* @return DL domain parameters of this key
	*/
	const ref DL_Group get_domain() const { return group; }

	/**
	* Get the public value y with y = g^x mod p where x is the secret key.
	*/
	const ref BigInt get_y() const { return y; }

	/**
	* Get the prime p of the underlying DL group.
	* @return prime p
	*/
	const ref BigInt group_p() const { return group.get_p(); }

	/**
	* Get the prime q of the underlying DL group.
	* @return prime q
	*/
	const ref BigInt group_q() const { return group.get_q(); }

	/**
	* Get the generator g of the underlying DL group.
	* @return generator g
	*/
	const ref BigInt group_g() const { return group.get_g(); }

	/**
	* Get the underlying groups encoding format.
	* @return encoding format
	*/
	abstract DL_Group.Format group_format() const;

	override size_t estimated_strength() const
	{
		return dl_work_factor(group.get_p().bits());
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     DL_Group.Format format)
	{
		group.BER_decode(alg_id.parameters, format);
		
		BER_Decoder(key_bits).decode(y);
	}

protected:
	this() {}

	/**
	* The DL public key
	*/
	BigInt y;

	/**
	* The DL group
	*/
	DL_Group group;
};

/**
* This class represents discrete logarithm (DL) private keys.
*/
class DL_Scheme_PrivateKey : DL_Scheme_PublicKey,
							 Private_Key
{
public:
	bool check_key(RandomNumberGenerator rng,
	               bool strong) const
	{
		if (y < 2 || y >= group_p())
			return false;
		if (!group.verify_group(rng, strong))
			return false;
		return true;
	}

	/**
	* Get the secret key x.
	* @return secret key
	*/
	const ref BigInt get_x() const { return x; }

	Secure_Vector!ubyte pkcs8_Private_Key() const
	{
		return DER_Encoder().encode(x).get_contents();
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     DL_Group.Format format)
	{
		group.BER_decode(alg_id.parameters, format);
		
		BER_Decoder(key_bits).decode(x);
	}

protected:
	this() {}

	/**
	* The DL private key
	*/
	BigInt x;
};