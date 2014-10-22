/*
* EAC1_1 CVC ADO
* (C) 2008 Falko Strenzke
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_ado;
import botan.cert.cvc.eac_obj;
import botan.cert.cvc.eac_asn_obj;
import botan.cert.cvc.cvc_req;
import botan.utils.types;
// import fstream;
import string;

/**
* This class represents a TR03110 (EAC) v1.1 CVC ADO request
*/

 // CRTP continuation from EAC1_1_obj
final class EAC1_1_ADO : public EAC1_1_obj!EAC1_1_ADO
{
public:
	/**
	* Construct a CVC ADO request from a DER encoded CVC ADO request file.
	* @param str the path to the DER encoded file
	*/
	this(in string input)
	{
		auto stream = scoped!DataSource_Stream(input, true);
		init(stream);
		do_decode();
	}

	/**
	* Construct a CVC ADO request from a data source
	* @param source the data source
	*/
	this(DataSource input)
	{
		init(input);
		do_decode();
	}

	/**
	* Create a signed CVC ADO request from to be signed (TBS) data
	* @param signer the signer used to sign the CVC ADO request
	* @param tbs_bits the TBS data to sign
	* @param rng a random number generator
	*/
	Vector!ubyte make_signed(PK_Signer signer,
	                         in Vector!ubyte tbs_bits,
	                         RandomNumberGenerator rng)
	{
		const Vector!ubyte concat_sig = signer.sign_message(tbs_bits, rng);
		
		return DER_Encoder()
			.start_cons(ASN1_Tag(7), ASN1_Tag.APPLICATION)
				.raw_bytes(tbs_bits)
				.encode(concat_sig, ASN1_Tag.OCTET_STRING, ASN1_Tag(55), ASN1_Tag.APPLICATION)
				.end_cons()
				.get_contents_unlocked();
	}

	/**
	* Get the CAR of this CVC ADO request
	* @result the CAR of this CVC ADO request
	*/
	ASN1_Car get_car() const
	{
		return m_car;
	}

	/**
	* Get the CVC request contained in this object.
	* @result the CVC request inside this CVC ADO request
	*/	
	EAC1_1_Req get_request() const
	{
		return m_req;
	}

	/**
	* Encode this object into a pipe. Only DER is supported.
	* @param output the pipe to encode this object into
	* @param encoding the encoding type to use, must be DER
	*/
	void encode(Pipe output, X509_Encoding encoding) const
	{
		if (encoding == PEM)
			throw new Invalid_Argument("encode() cannot PEM encode an EAC object");
		
		auto concat_sig = m_sig.get_concatenation();
		
		output.write(DER_Encoder()
		             .start_cons(ASN1_Tag(7), ASN1_Tag.APPLICATION)
		             .raw_bytes(tbs_bits)
		             .encode(concat_sig, ASN1_Tag.OCTET_STRING, ASN1_Tag(55), ASN1_Tag.APPLICATION)
		             .end_cons()
		             .get_contents());
	}

	bool opEquals(const ref EAC1_1_ADO rhs) const
	{
		return (get_concat_sig() == rhs.get_concat_sig()
		        && tbs_data() == rhs.tbs_data()
		        && get_car() ==  rhs.get_car());
	}

	/**
	* Get the TBS data of this CVC ADO request.
	* @result the TBS data
	*/
	Vector!ubyte tbs_data() const
	{
		return tbs_bits;
	}


	bool opCmp(string op)(const ref EAC1_1_ADO rhs)
		if (op == "!=")
	{
		return (!(this == rhs));
	}

	~this() {}
private:
	ASN1_Car m_car;
	EAC1_1_Req m_req;

	void force_decode()
	{
		Vector!ubyte inner_cert;
		BER_Decoder(tbs_bits)
			.start_cons(ASN1_Tag(33))
				.raw_bytes(inner_cert)
				.end_cons()
				.decode(m_car)
				.verify_end();
		
		Vector!ubyte req_bits = DER_Encoder()
			.start_cons(ASN1_Tag(33), ASN1_Tag.APPLICATION)
				.raw_bytes(inner_cert)
				.end_cons()
				.get_contents_unlocked();
		
		auto req_source = scoped!DataSource_Memory(req_bits);
		m_req = EAC1_1_Req(req_source);
		sig_algo = m_req.sig_algo;
	}


	void decode_info(DataSource source,
	                 ref Vector!ubyte res_tbs_bits,
	                 ref ECDSA_Signature res_sig)
	{
		Vector!ubyte concat_sig;
		Vector!ubyte cert_inner_bits;
		ASN1_Car car;
		
		BER_Decoder(source)
			.start_cons(ASN1_Tag(7))
				.start_cons(ASN1_Tag(33))
				.raw_bytes(cert_inner_bits)
				.end_cons()
				.decode(car)
				.decode(concat_sig, ASN1_Tag.OCTET_STRING, ASN1_Tag(55), ASN1_Tag.APPLICATION)
				.end_cons();
		
		Vector!ubyte enc_cert = DER_Encoder()
			.start_cons(ASN1_Tag(33), ASN1_Tag.APPLICATION)
				.raw_bytes(cert_inner_bits)
				.end_cons()
				.get_contents_unlocked();
		
		res_tbs_bits = enc_cert;
		res_tbs_bits += DER_Encoder().encode(car).get_contents();
		res_sig = decode_concatenation(concat_sig);
	}
};
