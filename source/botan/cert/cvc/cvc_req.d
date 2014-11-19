/*
* EAC1_1 CVC Request
* (C) 2008 Falko Strenzke
*	  2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_req;

import botan.cert.cvc.cvc_gen_cert;
import botan.asn1.oids;
import botan.asn1.ber_dec;
import botan.utils.types;

alias EAC1_1_Req = FreeListRef!EAC1_1_Req_Impl;
/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
final class EAC1_1_Req_Impl : EAC1_1_gen_CVC!EAC1_1_Req_Impl
{
public:

	/**
	* Compare for equality with other
	* @param other compare for equality with this object
	*/
	bool opEquals(in EAC1_1_Req rhs) const
	{
		return (this.tbs_data() == rhs.tbs_data() &&
		        this.get_concat_sig() == rhs.get_concat_sig());
	}

	bool opCmp(string op)(in EAC1_1_Req_Impl rhs)
		if (op == "!=")
	{
		return !(this == rhs);

	}
	/**
	* Construct a CVC request from a data source.
	* @param source the data source
	*/
	this(DataSource source)
	{
		init(input);
		self_signed = true;
		do_decode();
	}

	/**
	* Construct a CVC request from a DER encoded CVC request file.
	* @param str the path to the DER encoded file
	*/
	this(in string str)
	{
		auto stream = scoped!DataSource_Stream(input, true);
		init(stream);
		self_signed = true;
		do_decode();
	}

	~this(){}
private:
	void force_decode()
	{
		Vector!ubyte enc_pk;
		BER_Decoder tbs_cert = BER_Decoder(tbs_bits);
		size_t cpi;
		tbs_cert.decode(cpi, ASN1_Tag(41), ASN1_Tag.APPLICATION)
			.start_cons(ASN1_Tag(73))
				.raw_bytes(enc_pk)
				.end_cons()
				.decode(m_chr)
				.verify_end();
		
		if (cpi != 0)
			throw new Decoding_Error("EAC1_1 requests cpi was not 0");
		
		m_pk = decode_eac1_1_key(enc_pk, sig_algo);
	}

	this() {}
}