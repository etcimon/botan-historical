/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecdsa;

import botan.constants;
static if (BOTAN_HAS_ECDSA):

import botan.pubkey.algo.ecc_key;
import botan.math.numbertheory.reducer;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.keypair;
import botan.math.ec_gfp.point_gfp;
import botan.rng.rng;

/**
* This class represents ECDSA Public Keys.
*/
class ECDSA_PublicKey : EC_PublicKey
{
public:

	/**
	* Construct a public key from a given public point.
	* @param dom_par the domain parameters associated with this key
	* @param public_point the public point defining this key
	*/
	this(in EC_Group dom_par,
		 const ref PointGFp public_point) 
	{
		super(dom_par, public_point);
	}

	this(in Algorithm_Identifier alg_id,
		 in Secure_Vector!ubyte key_bits)
	{
		super(alg_id, key_bits);
	}

	/**
	* Get this keys algorithm name.
	* @result this keys algorithm name ("ECDSA")
	*/
	@property string algo_name() const { return "ECDSA"; }

	/**
	* Get the maximum number of bits allowed to be fed to this key.
	* This is the bitlength of the order of the base point.
	* @result the maximum number of input bits
	*/
	size_t max_input_bits() const { return domain().get_order().bits(); }

	size_t message_parts() const { return 2; }

	size_t message_part_size() const
	{ return domain().get_order().bytes(); }

protected:
	this() {}
}

/**
* This class represents ECDSA Private Keys
*/
final class ECDSA_PrivateKey : ECDSA_PublicKey,
						 EC_PrivateKey
{
public:

	/**
	* Load a private key
	* @param alg_id the X.509 algorithm identifier
	* @param key_bits PKCS #8 structure
	*/
	this(in Algorithm_Identifier alg_id,
		 in Secure_Vector!ubyte key_bits)
	{
		super(alg_id, key_bits);
	}

	/**
	* Generate a new private key
	* @param rng a random number generator
	* @param domain parameters to used for this key
	* @param x the private key (if zero, generate a ney random key)
	*/
	this(RandomNumberGenerator rng,
						  const ref EC_Group domain,
						  const ref BigInt x = 0)
	{
		super(rng, domain, x);
	}

	bool check_key(RandomNumberGenerator rng,
	               bool strong) const
	{
		if (!public_point().on_the_curve())
			return false;
		
		if (!strong)
			return true;
		
		return signature_consistency_check(rng, this, "EMSA1(SHA-1)");
	}
}

/**
* ECDSA signature operation
*/
final class ECDSA_Signature_Operation : Signature
{
public:
	this(in ECDSA_PrivateKey ecdsa)
	{
		m_base_point = ecdsa.domain().get_base_point();
		m_order = ecdsa.domain().get_order();
		m_x = ecdsa.private_value();
		m_mod_order = order;
	}

	Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len,
	                      RandomNumberGenerator rng)
	{
		rng.add_entropy(msg, msg_len);
		
		BigInt m = BigInt(msg, msg_len);
		
		BigInt r = 0, s = 0;
		
		while(r == 0 || s == 0)
		{
			// This contortion is necessary for the tests
			BigInt k;
			k.randomize(rng, m_order.bits());
			
			while(k >= m_order)
				k.randomize(rng, m_order.bits() - 1);
			
			PointGFp k_times_P = m_base_point * k;
			r = m_mod_order.reduce(k_times_P.get_affine_x());
			s = m_mod_order.multiply(inverse_mod(k, m_order), mul_add(m_x, r, m));
		}
		
		Secure_Vector!ubyte output = Secure_Vector!ubyte(2*m_order.bytes());
		r.binary_encode(&output[output.length / 2 - r.bytes()]);
		s.binary_encode(&output[output.length - s.bytes()]);
		return output;
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_order.bytes(); }
	size_t max_input_bits() const { return m_order.bits(); }

private:
	const PointGFp m_base_point;
	const BigInt m_order;
	const BigInt m_x;
	Modular_Reducer m_mod_order;
}

/**
* ECDSA verification operation
*/
final class ECDSA_Verification_Operation : Verification
{
public:
	this(in ECDSA_PublicKey ecdsa) 
	{
		m_base_point = ecdsa.domain().get_base_point();
		m_public_point = ecdsa.public_point();
		m_order = ecdsa.domain().get_order();
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return m_order.bytes(); }
	size_t max_input_bits() const { return m_order.bits(); }

	bool with_recovery() const { return false; }

	bool verify(in ubyte* msg, size_t msg_len,
	            in ubyte* sig, size_t sig_len)
	{
		if (sig_len != m_order.bytes()*2)
			return false;
		
		BigInt e = BigInt(msg, msg_len);
		
		BigInt r = BigInt(sig, sig_len / 2);
		BigInt s = BigInt(sig + sig_len / 2, sig_len / 2);
		
		if (r <= 0 || r >= m_order || s <= 0 || s >= m_order)
			return false;
		
		BigInt w = inverse_mod(s, m_order);
		
		PointGFp R = w * multi_exponentiate(m_base_point, e,
		                                    m_public_point, r);
		
		if (R.is_zero())
			return false;
		
		return (R.get_affine_x() % m_order == r);
	}

private:
	const PointGFp m_base_point;
	const PointGFp m_public_point;
	const BigInt m_order;
}
