/*
* EAC1_1 CVC
* (C) 2008 Falko Strenzke
*	  2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_cert;

import botan.cert.cvc.cvc_gen_cert;
import botan.asn1.oid_lookup.oids;
import botan.ecdsa;
import string;
/**
* This class represents TR03110 (EAC) v1.1 CV Certificates
*/
class EAC1_1_CVC : public EAC1_1_gen_CVC!EAC1_1_CVC//Signed_Object
{
public:
	/**
	* Get the CAR of the certificate.
	* @result the CAR of the certificate
	*/
	ASN1_Car get_car() const
	{
		return m_car;
	}

	/**
	* Get the CED of this certificate.
	* @result the CED this certificate
	*/
	ASN1_Ced get_ced() const
	{
		return m_ced;
	}

	/**
	* Get the CEX of this certificate.
	* @result the CEX this certificate
	*/
	ASN1_Cex get_cex() const
	{
		return m_cex;
	}

	/**
	* Get the CHAT value.
	* @result the CHAT value
	*/
	uint get_chat_value() const
	{
		return m_chat_val;
	}

	bool opEquals(in EAC1_1_CVC) const
	{
		return (tbs_data() == rhs.tbs_data()
		        && get_concat_sig() == rhs.get_concat_sig());
	}

	/*
	* Comparison
	*/
	bool opCmp(string op)(ref const EAC1_1_CVC rhs)
		if (op == "!=")
	{
		return !(lhs == rhs);
	}

	/**
	* Construct a CVC from a data source
	* @param source the data source
	*/
	this(DataSource input)
	{
		init(input);
		self_signed = false;
		do_decode();
	}

	/**
	* Construct a CVC from a file
	* @param str the path to the certificate file
	*/
	this(in string input)
	{
		DataSource_Stream stream = DataSource_Stream(input, true);
		init(stream);
		self_signed = false;
		do_decode();
	}

	~this() {}
private:

	/*
* Decode the TBSCertificate data
*/
	void force_decode()
	{
		Vector!ubyte enc_pk;
		Vector!ubyte enc_chat_val;
		size_t cpi;
		BER_Decoder tbs_cert(tbs_bits);
		tbs_cert.decode(cpi, ASN1_Tag(41), ASN1_Tag.APPLICATION)
			.decode(m_car)
				.start_cons(ASN1_Tag(73))
				.raw_bytes(enc_pk)
				.end_cons()
				.decode(m_chr)
				.start_cons(ASN1_Tag(76))
				.decode(m_chat_oid)
				.decode(enc_chat_val, ASN1_Tag.OCTET_STRING, ASN1_Tag(19), ASN1_Tag.APPLICATION)
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

	this() {}

	ASN1_Car m_car;
	ASN1_Ced m_ced;
	ASN1_Cex m_cex;
	ubyte m_chat_val;
	OID m_chat_oid;
};

/**
* Create an arbitrary EAC 1.1 CVC.
* The desired key encoding must be set within the key (if applicable).
* @param signer the signer used to sign the certificate
* @param public_key the DER encoded public key to appear in
* the certificate
* @param car the CAR of the certificate
* @param chr the CHR of the certificate
* @param holder_auth_templ the holder authorization value ubyte to
* appear in the CHAT of the certificate
* @param ced the CED to appear in the certificate
* @param cex the CEX to appear in the certificate
* @param rng a random number generator
*/

EAC1_1_CVC make_cvc_cert(PK_Signer signer,
                         in Vector!ubyte public_key,
                         ref const ASN1_Car car,
                         ref const ASN1_Chr chr,
                         ubyte holder_auth_templ,
                         ASN1_Ced ced,
                         ASN1_Cex cex,
                         RandomNumberGenerator rng)
{
	OID chat_oid(oids.lookup("CertificateHolderAuthorizationTemplate"));
	Vector!ubyte enc_chat_val;
	enc_chat_val.push_back(holder_auth_templ);
	
	Vector!ubyte enc_cpi;
	enc_cpi.push_back(0x00);
	Vector!ubyte tbs = DER_Encoder()
		.encode(enc_cpi, ASN1_Tag.OCTET_STRING, ASN1_Tag(41), ASN1_Tag.APPLICATION) // cpi
			.encode(car)
			.raw_bytes(public_key)
			.encode(chr)
			.start_cons(ASN1_Tag(76), ASN1_Tag.APPLICATION)
			.encode(chat_oid)
			.encode(enc_chat_val, ASN1_Tag.OCTET_STRING, ASN1_Tag(19), ASN1_Tag.APPLICATION)
			.end_cons()
			.encode(ced)
			.encode(cex)
			.get_contents_unlocked();
	
	Vector!ubyte signed_cert =
		make_signed(signer,
		            build_cert_body(tbs),
		            rng);
	
	DataSource_Memory source = DataSource_Memory(signed_cert);
	return EAC1_1_CVC(source);
}



/**
* Decode an EAC encoding ECDSA key
*/

ECDSA_PublicKey* decode_eac1_1_key(in Vector!ubyte,
                                   ref AlgorithmIdentifier)
{
	throw new Internal_Error("decode_eac1_1_key: Unimplemented");
	return 0;
}
