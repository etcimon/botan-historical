/*
* ECDSA Signature
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ecdsa_sig;
ECDSA_Signature::ECDSA_Signature(in Vector!byte ber)
{
	BER_Decoder(ber)
		.start_cons(SEQUENCE)
			.decode(m_r)
			.decode(m_s)
		.end_cons()
		.verify_end();
}

Vector!( byte ) ECDSA_Signature::DER_encode() const
{
	return DER_Encoder()
		.start_cons(SEQUENCE)
		  .encode(get_r())
		  .encode(get_s())
		.end_cons()
		.get_contents_unlocked();
}

Vector!( byte ) ECDSA_Signature::get_concatenation() const
{
	// use the larger
	const size_t enc_len = m_r > m_s ? m_r.bytes() : m_s.bytes();

	const auto sv_r = BigInt::encode_1363(m_r, enc_len);
	const auto sv_s = BigInt::encode_1363(m_s, enc_len);

	SafeVector!byte result(sv_r);
	result += sv_s;
	return unlock(result);
}

ECDSA_Signature decode_concatenation(in Vector!byte concat)
{
	if (concat.size() % 2 != 0)
		throw new Invalid_Argument("Erroneous length of signature");

	const size_t rs_len = concat.size() / 2;

	BigInt r = BigInt::decode(&concat[0], rs_len);
	BigInt s = BigInt::decode(&concat[rs_len], rs_len);

	return ECDSA_Signature(r, s);
}

}
