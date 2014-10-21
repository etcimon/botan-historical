/*
* CRL Entry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.crl_ent;

import botan.cert.x509.x509cert;
import botan.asn1.asn1_time;
import botan.cert.x509.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.asn1.oid_lookup.oids;

/**
* X.509v2 CRL Reason Code.
*/
enum CRL_Code {
	UNSPECIFIED				= 0,
	KEY_COMPROMISE			= 1,
	CA_COMPROMISE			= 2,
	AFFILIATION_CHANGED	 	= 3,
	SUPERSEDED				= 4,
	CESSATION_OF_OPERATION 	= 5,
	CERTIFICATE_HOLD		= 6,
	REMOVE_FROM_CRL		  	= 8,
	PRIVLEDGE_WITHDRAWN	 	= 9,
	AA_COMPROMISE			= 10,

	DELETE_CRL_ENTRY		= 0xFF00,
	OCSP_GOOD				= 0xFF01,
	OCSP_UNKNOWN			= 0xFF02
};

/**
* This class represents CRL entries
*/
class CRL_Entry : ASN1_Object
{
public:
	/*
	* DER encode a CRL_Entry
	*/
	void encode_into(DER_Encoder to) const
	{
		Extensions extensions;
		
		extensions.add(new x509_ext.CRL_ReasonCode(reason));
		
		to.start_cons(ASN1_Tag.SEQUENCE)
			.encode(BigInt.decode(serial))
				.encode(time)
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(extensions)
				.end_cons()
				.end_cons();
	}
	

	/*
	* Decode a BER encoded CRL_Entry
	*/
	void decode_from(BER_Decoder source)
	{
		BigInt serial_number_bn;
		reason = CRL_Code.UNSPECIFIED;
		
		BER_Decoder entry = source.start_cons(ASN1_Tag.SEQUENCE);
		
		entry.decode(serial_number_bn).decode(time);
		
		if (entry.more_items())
		{
			Extensions extensions = Extensions(throw_on_unknown_critical);
			entry.decode(extensions);
			Data_Store info;
			extensions.contents_to(info, info);
			reason = CRL_Code(info.get1_uint("X509v3.CRLReasonCode"));
		}
		
		entry.end_cons();
		
		serial = BigInt.encode(serial_number_bn);
	}

	/**
	* Get the serial number of the certificate associated with this entry.
	* @return certificate's serial number
	*/
	Vector!ubyte serial_number() const { return serial; }

	/**
	* Get the revocation date of the certificate associated with this entry
	* @return certificate's revocation date
	*/
	X509_Time expire_time() const { return time; }

	/**
	* Get the entries reason code
	* @return reason code
	*/
	CRL_Code reason_code() const { return reason; }

	/**
	* Construct an empty CRL entry.
	*/
	this(bool throw_on_unknown_critical_extension)
	{
		throw_on_unknown_critical = throw_on_unknown_critical_extension;
		reason = CRL_Code.UNSPECIFIED;
	}

	/**
	* Construct an CRL entry.
	* @param cert the certificate to revoke
	* @param reason the reason code to set in the entry
	*/
	this(in X509_Certificate cert, CRL_Code why = CRL_Code.UNSPECIFIED)
	{
		throw_on_unknown_critical = false;
		serial = cert.serial_number();
		time = X509_Time(Clock.currTime());
		reason = why;
	}

	/*
	* Compare two CRL_Entrys for equality
	*/
	bool opEquals(const ref CRL_Entry a2)
	{
		if (serial_number() != a2.serial_number())
			return false;
		if (expire_time() != a2.expire_time())
			return false;
		if (reason_code() != a2.reason_code())
			return false;
		return true;
	}
	
	/*
	* Compare two CRL_Entrys for inequality
	*/
	bool opCmp(string op)(const ref CRL_Entry a2)
		if (op == "!=")
	{
		return !(this == a2);
	}


private:
	bool throw_on_unknown_critical;
	Vector!ubyte serial;
	X509_Time time;
	CRL_Code reason;
};