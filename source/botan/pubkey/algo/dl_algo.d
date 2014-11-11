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
		if (m_y < 2 || m_y >= group_p())
			return false;
		if (!m_group.verify_group(rng, strong))
			return false;
		return true;
	}

	Algorithm_Identifier algorithm_identifier() const
	{
		return Algorithm_Identifier(get_oid(),
		                           m_group.DER_encode(group_format()));
	}

	Vector!ubyte x509_subject_public_key() const
	{
		return DER_Encoder().encode(m_y).get_contents_unlocked();
	}

	/**
	* Get the DL domain parameters of this key.
	* @return DL domain parameters of this key
	*/
	const ref DL_Group get_domain() const { return m_group; }

	/**
	* Get the public value m_y with m_y = g^m_x mod p where m_x is the secret key.
	*/
	const ref BigInt get_y() const { return m_y; }

	/**
	* Get the prime p of the underlying DL m_group.
	* @return prime p
	*/
	const ref BigInt group_p() const { return m_group.get_p(); }

	/**
	* Get the prime q of the underlying DL m_group.
	* @return prime q
	*/
	const ref BigInt group_q() const { return m_group.get_q(); }

	/**
	* Get the generator g of the underlying DL m_group.
	* @return generator g
	*/
	const ref BigInt group_g() const { return m_group.get_g(); }

	/**
	* Get the underlying groups encoding format.
	* @return encoding format
	*/
	abstract DL_Group.Format group_format() const;

	override size_t estimated_strength() const
	{
		return dl_work_factor(m_group.get_p().bits());
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     DL_Group.Format format)
	{
		m_group.BER_decode(alg_id.parameters, format);
		
		BER_Decoder(key_bits).decode(m_y);
	}

protected:
	this() {}

	/**
	* The DL public key
	*/
	BigInt m_y;

	/**
	* The DL m_group
	*/
	DL_Group m_group;
}

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
		const BigInt p = group_p();
		const BigInt g = group_g();
		
		if (m_y < 2 || m_y >= p || m_x < 2 || m_x >= p)
			return false;
		if (!m_group.verify_group(rng, strong))
			return false;
		
		if (!strong)
			return true;
		
		if (m_y != power_mod(g, m_x, p))
			return false;
		
		return true;
	}

	/**
	* Get the secret key m_x.
	* @return secret key
	*/
	const ref BigInt get_x() const { return m_x; }

	Secure_Vector!ubyte pkcs8_private_key() const
	{
		return DER_Encoder().encode(m_x).get_contents();
	}

	this(in Algorithm_Identifier alg_id,
	     in Secure_Vector!ubyte key_bits,
	     DL_Group.Format format)
	{
		m_group.BER_decode(alg_id.parameters, format);
		
		BER_Decoder(key_bits).decode(m_x);
	}

protected:
	this() {}

	/**
	* The DL private key
	*/
	BigInt m_x;
}