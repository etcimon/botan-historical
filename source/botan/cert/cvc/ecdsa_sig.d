/*
* ECDSA Signature
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.ecdsa_sig;

import botan.constants;
static if (BOTAN_HAS_CVC_CERTIFICATES):

import botan.math.bigint.bigint;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
/**
* Class representing an ECDSA signature
*/
class ECDSA_Signature
{
public:
	this() {}
	this(in BigInt r, in BigInt s) {
		m_r = r;
		m_s = s;
	}

	this(in Vector!ubyte ber)
	{
		BER_Decoder(ber)
				.start_cons(ASN1_Tag.SEQUENCE)
				.decode(m_r)
				.decode(m_s)
				.end_cons()
				.verify_end();
	}

	const BigInt get_r() const { return m_r; }
	const BigInt get_s() const { return m_s; }

	/**
	* return the r||s
	*/
	Vector!ubyte get_concatenation() const
	{
		// use the larger
		const size_t enc_len = m_r > m_s ? m_r.bytes() : m_s.bytes();
		
		const auto sv_r = BigInt.encode_1363(m_r, enc_len);
		const auto sv_s = BigInt.encode_1363(m_s, enc_len);
		
		Secure_Vector!ubyte result = Secure_Vector!ubyte(sv_r);
		result ~= sv_s;
		return unlock(result);
	}

	Vector!ubyte DER_encode() const
	{
		return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(get_r())
				.encode(get_s())
				.end_cons()
				.get_contents_unlocked();
	}


	bool opEquals(in ECDSA_Signature other) const
	{
		return (get_r() == other.get_r() && get_s() == other.get_s());
	}

	bool opCmp(string op)(in ECDSA_Signature rhs)
		if (op == "!=")
	{
		return !(this == rhs);
	}

private:
	BigInt m_r;
	BigInt m_s;
}

ECDSA_Signature decode_concatenation(in Vector!ubyte concat)
{
	if (concat.length % 2 != 0)
		throw new Invalid_Argument("Erroneous length of signature");
	
	const size_t rs_len = concat.length / 2;
	
	BigInt r = BigInt.decode(concat.ptr, rs_len);
	BigInt s = BigInt.decode(&concat[rs_len], rs_len);
	
	return ECDSA_Signature(r, s);
}