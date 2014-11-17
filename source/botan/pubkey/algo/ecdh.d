/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecdh;

import botan.constants;
static if (BOTAN_HAS_ECDH):

import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.math.bigint.bigint;

/**
* This class represents ECDH Public Keys.
*/
class ECDH_PublicKey : EC_PublicKey
{
public:

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits) 
	{ 
		super(alg_id, key_bits);
	}

	/**
	* Construct a public key from a given public point.
	* @param dom_par the domain parameters associated with this key
	* @param public_point the public point defining this key
	*/
	this(in EC_Group dom_par, const ref PointGFp public_point) 
	{
		super(dom_par, public_point);
	}

	/**
	* Get this keys algorithm name.
	* @return this keys algorithm name
	*/
	@property string algo_name() const { return "ECDH"; }

	/**
	* Get the maximum number of bits allowed to be fed to this key.
	* This is the bitlength of the order of the base point.

	* @return maximum number of input bits
	*/
	size_t max_input_bits() const { return domain().get_order().bits(); }

	/**
	* @return public point value
	*/
	Vector!ubyte public_value() const
	{ return unlock(EC2OSP(public_point(), PointGFp.UNCOMPRESSED)); }

protected:
	this() {}
}

/**
* This class represents ECDH Private Keys.
*/
final class ECDH_PrivateKey : ECDH_PublicKey,
							  EC_PrivateKey,
							  PK_Key_Agreement_Key
{
public:

	this(in Algorithm_Identifier alg_id, in Secure_Vector!ubyte key_bits) 
	{
		super(alg_id, key_bits);
	}

	/**
	* Generate a new private key
	* @param rng a random number generator
	* @param domain parameters to used for this key
	* @param x the private key; if zero, a new random key is generated
	*/
	this(RandomNumberGenerator rng, const ref EC_Group domain,
		in BigInt x = 0) 
	{
		super(rng, domain, x);
	}

	Vector!ubyte public_value() const
	{ return super.public_value(); }
}

/**
* ECDH operation
*/
final class ECDH_KA_Operation : Key_Agreement
{
public:
	this(in ECDH_PrivateKey key) 
	{
		m_curve = key.domain().get_curve();
		m_cofactor = key.domain().get_cofactor();
		l_times_priv = inverse_mod(m_cofactor, key.domain().get_order()) * key.private_value();
	}

	Secure_Vector!ubyte agree(in ubyte* w, size_t w_len)
	{
		PointGFp point = OS2ECP(w, w_len, m_curve);
		
		PointGFp S = (m_cofactor * point) * m_l_times_priv;

		assert(S.on_the_curve(), "ECDH agreed value was on the curve");
		
		return BigInt.encode_1363(S.get_affine_x(),
		                          m_curve.get_p().bytes());
	}
private:
	const CurveGFp m_curve;
	const BigInt m_cofactor;
	BigInt m_l_times_priv;
}