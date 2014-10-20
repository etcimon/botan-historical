/*
* GOST 34.10-2001
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*			 Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.gost_3410;

import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.gost_3410;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* GOST-34.10 Public Key
*/
class GOST_3410_PublicKey : EC_PublicKey
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

	/**
	* Construct from X.509 algorithm id and subject public key bits
	*/
	this(in AlgorithmIdentifier alg_id,
	     in SafeVector!ubyte key_bits)
	{
		OID ecc_param_id;
		
		// Also includes hash and cipher OIDs... brilliant design guys
		BER_Decoder(alg_id.parameters).start_cons(ASN1_Tag.SEQUENCE).decode(ecc_param_id);
		
		domain_params = EC_Group(ecc_param_id);
		
		SafeVector!ubyte bits;
		BER_Decoder(key_bits).decode(bits, ASN1_Tag.OCTET_STRING);
		
		const size_t part_size = bits.length / 2;
		
		// Keys are stored in little endian format (WTF)
		for (size_t i = 0; i != part_size / 2; ++i)
		{
			std.algorithm.swap(bits[i], bits[part_size-1-i]);
			std.algorithm.swap(bits[part_size+i], bits[2*part_size-1-i]);
		}
		
		BigInt x = BigInt(&bits[0], part_size);
		BigInt y = BigInt(&bits[part_size], part_size);
		
		public_key = PointGFp(domain().get_curve(), x, y);
		
		BOTAN_ASSERT(public_key.on_the_curve(),
		             "Loaded GOST 34.10 public key is on the curve");
	}

	/**
	* Get this keys algorithm name.
	* @result this keys algorithm name
	*/
	string algo_name() const { return "GOST-34.10"; }

	AlgorithmIdentifier algorithm_identifier() const
	{
		Vector!ubyte params =
			DER_Encoder().start_cons(ASN1_Tag.SEQUENCE)
				.encode(OID(domain().get_oid()))
				.end_cons()
				.get_contents_unlocked();
		
		return AlgorithmIdentifier(get_oid(), params);
	}

	Vector!ubyte x509_subject_public_key() const
	{
		// Trust CryptoPro to come up with something obnoxious
		const BigInt x = public_point().get_affine_x();
		const BigInt y = public_point().get_affine_y();
		
		size_t part_size = std.algorithm.max(x.bytes(), y.bytes());
		
		Vector!ubyte bits = Vector!ubyte(2*part_size);
		
		x.binary_encode(&bits[part_size - x.bytes()]);
		y.binary_encode(&bits[2*part_size - y.bytes()]);
		
		// Keys are stored in little endian format (WTF)
		for (size_t i = 0; i != part_size / 2; ++i)
		{
			std.algorithm.swap(bits[i], bits[part_size-1-i]);
			std.algorithm.swap(bits[part_size+i], bits[2*part_size-1-i]);
		}
		
		return DER_Encoder().encode(bits, ASN1_Tag.OCTET_STRING).get_contents_unlocked();
	}

	/**
	* Get the maximum number of bits allowed to be fed to this key.
	* This is the bitlength of the order of the base point.

	* @result the maximum number of input bits
	*/
	size_t max_input_bits() const { return domain().get_order().bits(); }

	size_t message_parts() const { return 2; }

	size_t message_part_size() const
	{ return domain().get_order().bytes(); }

package:
	this() {}
};

/**
* GOST-34.10 Private Key
*/
class GOST_3410_PrivateKey : GOST_3410_PublicKey,
							 EC_PrivateKey
{
public:

	this(in AlgorithmIdentifier alg_id,
								in SafeVector!ubyte key_bits)
	{
		super(alg_id, key_bits);
	}

	/**
	* Generate a new private key
	* @param rng a random number generator
	* @param domain parameters to used for this key
	* @param x the private key; if zero, a new random key is generated
	*/
	GOST_3410_PrivateKey(RandomNumberGenerator rng,
								const ref EC_Group domain,
								const ref BigInt x = 0)
	{
		super(rng, domain, x);
	}

	AlgorithmIdentifier pkcs8_algorithm_identifier() const
	{ return super.algorithm_identifier(); }
};

/**
* GOST-34.10 signature operation
*/
class GOST_3410_Signature_Operation : pk_ops.Signature
{
public:	
	this(const GOST_3410_PrivateKey gost_3410)
	{
		
		base_point = gost_3410.domain().get_base_point();
		order = gost_3410.domain().get_order();
		x = gost_3410.private_value();
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return order.bytes(); }
	size_t max_input_bits() const { return order.bits(); }

	SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
	                      RandomNumberGenerator rng)
	{
		BigInt k;
		do
			k.randomize(rng, order.bits()-1);
		while(k >= order);
		
		BigInt e = decode_le(msg, msg_len);
		
		e %= order;
		if (e == 0)
			e = 1;
		
		PointGFp k_times_P = base_point * k;
		
		BOTAN_ASSERT(k_times_P.on_the_curve(),
		             "GOST 34.10 k*g is on the curve");
		
		BigInt r = k_times_P.get_affine_x() % order;
		
		BigInt s = (r*x + k*e) % order;
		
		if (r == 0 || s == 0)
			throw new Invalid_State("GOST 34.10: r == 0 || s == 0");
		
		SafeVector!ubyte output = SafeVector!ubyte(2*order.bytes());
		s.binary_encode(&output[output.length / 2 - s.bytes()]);
		r.binary_encode(&output[output.length - r.bytes()]);
		return output;
	}

private:
	const ref PointGFp base_point;
	const ref BigInt order;
	const ref BigInt x;
};

/**
* GOST-34.10 verification operation
*/
class GOST_3410_Verification_Operation : pk_ops.Verification
{
public:
	this(in GOST_3410_PublicKey gost) 
	{
		base_point = gost.domain().get_base_point();
		public_point = gost.public_point();
		order = gost.domain().get_order();
	}

	size_t message_parts() const { return 2; }
	size_t message_part_size() const { return order.bytes(); }
	size_t max_input_bits() const { return order.bits(); }

	bool with_recovery() const { return false; }

	bool verify(in ubyte* msg, size_t msg_len,
	            in ubyte* sig, size_t sig_len)
	{
		if (sig_len != order.bytes()*2)
			return false;
		
		BigInt e = decode_le(msg, msg_len);
		
		BigInt s = BigInt(sig, sig_len / 2);
		BigInt r = BigInt(sig + sig_len / 2, sig_len / 2);
		
		if (r <= 0 || r >= order || s <= 0 || s >= order)
			return false;
		
		e %= order;
		if (e == 0)
			e = 1;
		
		BigInt v = inverse_mod(e, order);
		
		BigInt z1 = (s*v) % order;
		BigInt z2 = (-r*v) % order;
		
		PointGFp R = multi_exponentiate(base_point, z1,
		                                public_point, z2);
		
		if (R.is_zero())
			return false;
		
		return (R.get_affine_x() == r);
	}
private:
	const ref PointGFp base_point;
	const ref PointGFp public_point;
	const ref BigInt order;
};


private:

BigInt decode_le(in ubyte* msg, size_t msg_len)
{
	SafeVector!ubyte msg_le = SafeVector!ubyte(msg, msg + msg_len);
	
	for (size_t i = 0; i != msg_le.length / 2; ++i)
		std.algorithm.swap(msg_le[i], msg_le[msg_le.length-1-i]);
	
	return BigInt(&msg_le[0], msg_le.length);
}