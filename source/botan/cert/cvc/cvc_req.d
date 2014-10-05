/*
  (C) 2007 FlexSecure GmbH
		2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.cvc_req;
import botan.cvc_cert;
import botan.asn1.ber_dec;
bool EAC1_1_Req::operator==(EAC1_1_Req const& rhs) const
{
	return (this.tbs_data() == rhs.tbs_data() &&
			  this.get_concat_sig() == rhs.get_concat_sig());
}

void EAC1_1_Req::force_decode()
{
	Vector!byte enc_pk;
	BER_Decoder tbs_cert(tbs_bits);
	size_t cpi;
	tbs_cert.decode(cpi, ASN1_Tag(41), APPLICATION)
		.start_cons(ASN1_Tag(73))
		.raw_bytes(enc_pk)
		.end_cons()
		.decode(m_chr)
		.verify_end();

	if (cpi != 0)
		throw new Decoding_Error("EAC1_1 requests cpi was not 0");

	m_pk = decode_eac1_1_key(enc_pk, sig_algo);
}

EAC1_1_Req::EAC1_1_Req(DataSource& input)
{
	init(input);
	self_signed = true;
	do_decode();
}

EAC1_1_Req::EAC1_1_Req(in string input)
{
	DataSource_Stream stream(input, true);
	init(stream);
	self_signed = true;
	do_decode();
}

}
