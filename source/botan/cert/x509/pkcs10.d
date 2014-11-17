/*
* PKCS #10
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.pkcs10;

import botan.cert.x509.x509_obj;
import botan.asn1.x509_dn;
import botan.pubkey.pkcs8;
import botan.utils.datastor.datastor;
import botan.cert.x509.key_constraint;
import botan.asn1.asn1_attribute;
import botan.asn1.asn1_alt_name;
import botan.cert.x509.pkcs10;
import botan.cert.x509.x509_ext;
import botan.cert.x509.x509cert;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.asn1.oid_lookup.oids;
import botan.codec.pem;
import botan.utils.types;
import botan.utils.exceptn;

alias PKCS10_Request = FreeListRef!PKCS10_Request_Impl;

/**
* PKCS #10 Certificate Request.
*/
final class PKCS10_Request_Impl : X509_Object
{
public:
	/**
	* Get the subject public key.
	* @return subject public key
	*/
	Public_Key subject_public_key() const
	{
		DataSource_Memory source = m_info.get1("X509.Certificate.public_key");
		return x509_key.load_key(source);
	}


	/**
	* Get the raw DER encoded public key.
	* @return the public key of the requestor
	*/
	Vector!ubyte raw_public_key() const
	{
		auto source = scoped!DataSource_Memory(m_info.get1("X509.Certificate.public_key"));
		return unlock(PEM.decode_check_label(source, "PUBLIC KEY"));
	}

	/**
	* Get the subject DN.
	* @return the name of the requestor
	*/
	X509_DN subject_dn() const
	{
		return create_dn(m_info);
	}

	/**
	* Get the subject alternative name.
	* @return the alternative names of the requestor
	*/
	Alternative_Name subject_alt_name() const
	{
		return create_alt_name(m_info);
	}

	/**
	* Get the key constraints for the key associated with this
	* PKCS#10 object.
	* @return the key constraints (if any)
	*/
	Key_Constraints constraints() const
	{
		return Key_Constraints(m_info.get1_uint("X509v3.KeyUsage", Key_Constraints.NO_CONSTRAINTS));
	}

	/**
	* Get the extendend key constraints (if any).
	* @return the extendend key constraints (if any)
	*/
	Vector!OID ex_constraints() const
	{
		Vector!string oids = m_info.get("X509v3.ExtendedKeyUsage");
		
		Vector!OID result;
		foreach (oid; oids)
			result.push_back(OID(oid));
		return result;
	}

	/**
	* Find out whether this is a CA request.
	* @result true if it is a CA request, false otherwise.
	*/
	bool is_CA() const
	{
		return (m_info.get1_uint("X509v3.BasicConstraints.is_ca") > 0);
	}


	/**
	* Return the constraint on the path length defined
	* in the BasicConstraints extension.
	* @return the desired path limit (if any)
	*/
	uint path_limit() const
	{
		return m_info.get1_uint("X509v3.BasicConstraints.path_constraint", 0);
	}

	/**
	* Get the challenge password for this request
	* @return challenge password for this request
	*/
	string challenge_password() const
	{
		return m_info.get1("PKCS9.ChallengePassword");
	}

	/**
	* Create a PKCS#10 Request from a data source.
	* @param source the data source providing the DER encoded request
	*/
	this(DataSource source)
	{
		super(source, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
		do_decode();
	}

	/**
	* Create a PKCS#10 Request from a file.
	* @param filename the name of the file containing the DER or PEM
	* encoded request file
	*/
	this(in string input)
	{
		super(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
		do_decode();
	}

	/**
	* Create a PKCS#10 Request from binary data.
	* @param vec a std::vector containing the DER value
	*/
	this(in Vector!ubyte input)
	{
		super(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
		do_decode();
	}
private:
	/*
	* Deocde the CertificateRequestInfo
	*/
	void force_decode()
	{
		BER_Decoder cert_req_info = BER_Decoder(tbs_bits);
		
		size_t _version;
		cert_req_info.decode(_version);
		if (_version != 0)
			throw new Decoding_Error("Unknown version code in PKCS #10 request: " ~ to!string(_version));
		
		X509_DN dn_subject;
		cert_req_info.decode(dn_subject);
		
		m_info.add(dn_subject.contents());
		
		BER_Object public_key = cert_req_info.get_next_object();
		if (public_key.type_tag != ASN1_Tag.SEQUENCE || public_key.class_tag != ASN1_Tag.CONSTRUCTED)
			throw new BER_Bad_Tag("PKCS10_Request: Unexpected tag for public key",
			                      public_key.type_tag, public_key.class_tag);
		
		m_info.add("X509.Certificate.public_key", 
		           PEM.encode(asn1_obj.put_in_sequence(unlock(public_key.value)), "PUBLIC KEY"));
		
		BER_Object attr_bits = cert_req_info.get_next_object();
		
		if (attr_bits.type_tag == 0 &&
		    attr_bits.class_tag == ASN1_Tag(CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC))
		{
			auto attributes = BER_Decoder(attr_bits.value);
			while (attributes.more_items())
			{
				Attribute attr;
				attributes.decode(attr);
				handle_attribute(attr);
			}
			attributes.verify_end();
		}
		else if (attr_bits.type_tag != ASN1_Tag.NO_OBJECT)
			throw new BER_Bad_Tag("PKCS10_Request: Unexpected tag for attributes",
			                      attr_bits.type_tag, attr_bits.class_tag);
		
		cert_req_info.verify_end();
		
		if (!this.check_signature(subject_public_key()))
			throw new Decoding_Error("PKCS #10 request: Bad signature detected");
	}

	/*
	* Handle attributes in a PKCS #10 request
	*/
	void handle_attribute(in Attribute attr)
	{
		auto value = BER_Decoder(attr.parameters);
		
		if (attr.oid == oids.lookup("PKCS9.EmailAddress"))
		{
			ASN1_String email;
			value.decode(email);
			m_info.add("RFC822", email.value());
		}
		else if (attr.oid == oids.lookup("PKCS9.ChallengePassword"))
		{
			ASN1_String challenge_password;
			value.decode(challenge_password);
			m_info.add("PKCS9.ChallengePassword", challenge_password.value());
		}
		else if (attr.oid == oids.lookup("PKCS9.ExtensionRequest"))
		{
			auto extensions = scoped!Extensions;
			value.decode(extensions).verify_end();
			
			Data_Store issuer_info;
			extensions.contents_to(m_info, issuer_info);
		}
	}


	Data_Store m_info;
}
