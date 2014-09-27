/*
 (C) 2007 FlexSecure GmbH
	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.cvc_cert;
import botan.oids;
ASN1_Car EAC1_1_CVC::get_car() const
{
	return m_car;
}

ASN1_Ced EAC1_1_CVC::get_ced() const
{
	return m_ced;
}
ASN1_Cex EAC1_1_CVC::get_cex() const
{
	return m_cex;
}
uint EAC1_1_CVC::get_chat_value() const
{
	return m_chat_val;
}

/*
* Decode the TBSCertificate data
*/
void EAC1_1_CVC::force_decode()
{
	Vector!( byte ) enc_pk;
	Vector!( byte ) enc_chat_val;
	size_t cpi;
	BER_Decoder tbs_cert(tbs_bits);
	tbs_cert.decode(cpi, ASN1_Tag(41), APPLICATION)
		.decode(m_car)
		.start_cons(ASN1_Tag(73))
		.raw_bytes(enc_pk)
		.end_cons()
		.decode(m_chr)
		.start_cons(ASN1_Tag(76))
		.decode(m_chat_oid)
		.decode(enc_chat_val, OCTET_STRING, ASN1_Tag(19), APPLICATION)
		.end_cons()
		.decode(m_ced)
		.decode(m_cex)
		.verify_end();

	if (enc_chat_val.size() != 1)
		throw new Decoding_Error("CertificateHolderAuthorizationValue was not of length 1");

	if (cpi != 0)
		throw new Decoding_Error("EAC1_1 certificate's cpi was not 0");

	m_pk = decode_eac1_1_key(enc_pk, sig_algo);

	m_chat_val = enc_chat_val[0];

	self_signed = (m_car.iso_8859() == m_chr.iso_8859());
}

/*
* CVC Certificate Constructor
*/
EAC1_1_CVC::EAC1_1_CVC(DataSource& input)
{
	init(input);
	self_signed = false;
	do_decode();
}

EAC1_1_CVC::EAC1_1_CVC(in string input)
{
	DataSource_Stream stream(input, true);
	init(stream);
	self_signed = false;
	do_decode();
}

bool EAC1_1_CVC::operator==(EAC1_1_CVC const& rhs) const
{
	return (tbs_data() == rhs.tbs_data()
			  && get_concat_sig() == rhs.get_concat_sig());
}

ECDSA_PublicKey* decode_eac1_1_key(in Vector!byte,
											  AlgorithmIdentifier&)
{
	throw new Internal_Error("decode_eac1_1_key: Unimplemented");
	return 0;
}

EAC1_1_CVC make_cvc_cert(PK_Signer& signer,
								 in Vector!byte public_key,
								 ASN1_Car const& car,
								 ASN1_Chr const& chr,
								 byte holder_auth_templ,
								 ASN1_Ced ced,
								 ASN1_Cex cex,
								 RandomNumberGenerator& rng)
{
	OID chat_oid(OIDS::lookup("CertificateHolderAuthorizationTemplate"));
	Vector!( byte ) enc_chat_val;
	enc_chat_val.push_back(holder_auth_templ);

	Vector!( byte ) enc_cpi;
	enc_cpi.push_back(0x00);
	Vector!( byte ) tbs = DER_Encoder()
		.encode(enc_cpi, OCTET_STRING, ASN1_Tag(41), APPLICATION) // cpi
		.encode(car)
		.raw_bytes(public_key)
		.encode(chr)
		.start_cons(ASN1_Tag(76), APPLICATION)
		.encode(chat_oid)
		.encode(enc_chat_val, OCTET_STRING, ASN1_Tag(19), APPLICATION)
		.end_cons()
		.encode(ced)
		.encode(cex)
		.get_contents_unlocked();

	Vector!( byte ) signed_cert =
		EAC1_1_CVC::make_signed(signer,
										EAC1_1_CVC::build_cert_body(tbs),
										rng);

	DataSource_Memory source(signed_cert);
	return EAC1_1_CVC(source);
}

}
