/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_crl;

import botan.cert.x509.x509_obj;
import botan.cert.x509.crl_ent;
import botan.cert.x509.x509_ext;
import botan.cert.x509.x509cert;
import botan.asn1.x509_dn;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.math.bigint.bigint;
import botan.asn1.oids;
import botan.asn1.asn1_time;
import botan.utils.types;

alias X509_CRL = FreeListRef!X509_CRL_Impl;

/**
* This class represents X.509 Certificate Revocation Lists (CRLs).
*/
final class X509_CRL_Impl : X509_Object
{
public:
	/**
	* This class represents CRL related errors.
	*/
	class X509_CRL_Error : Exception
	{
		this(in string error) {
			super("X509_CRL: " ~ error);
		}
	}

	/**
	* Check if this particular certificate is listed in the CRL
	*/
	bool is_revoked(in X509_Certificate cert) const
	{
		/*
		If the cert wasn't issued by the CRL issuer, it's possible the cert
		is revoked, but not by this CRL. Maybe throw new an exception instead?
		*/
		if (cert.issuer_dn() != issuer_dn())
			return false;
		
		Vector!ubyte crl_akid = authority_key_id();
		Vector!ubyte cert_akid = cert.authority_key_id();
		
		if (!crl_akid.empty && !cert_akid.empty)
			if (crl_akid != cert_akid)
				return false;
		
		Vector!ubyte cert_serial = cert.serial_number();
		
		bool is_revoked = false;
		
		foreach (const revoked; m_revoked)
		{
			if (cert_serial == revoked.serial_number())
			{
				if (revoked.reason_code() == CRL_Code.REMOVE_FROM_CRL)
					is_revoked = false;
				else
					is_revoked = true;
			}
		}
		
		return is_revoked;
	}


	/**
	* Get the entries of this CRL in the form of a vector.
	* @return vector containing the entries of this CRL.
	*/
	Vector!CRL_Entry get_revoked() const
	{
		return m_revoked;
	}

	/**
	* Get the issuer DN of this CRL.
	* @return CRLs issuer DN
	*/
	X509_DN issuer_dn() const
	{
		return create_dn(m_info);
	}


	/**
	* Get the AuthorityKeyIdentifier of this CRL.
	* @return this CRLs AuthorityKeyIdentifier
	*/
	Vector!ubyte authority_key_id() const
	{
		return m_info.get1_memvec("X509v3.AuthorityKeyIdentifier");
	}

	/**
	* Get the serial number of this CRL.
	* @return CRLs serial number
	*/
	uint crl_number() const
	{
		return m_info.get1_uint("X509v3.CRLNumber");
	}

	/**
	* Get the CRL's thisUpdate value.
	* @return CRLs thisUpdate
	*/
	X509_Time this_update() const
	{
		return m_info.get1("X509.CRL.start");
	}

	/**
	* Get the CRL's nextUpdate value.
	* @return CRLs nextdUpdate
	*/
	X509_Time next_update() const
	{
		return m_info.get1("X509.CRL.end");
	}

	/**
	* Construct a CRL from a data source.
	* @param source the data source providing the DER or PEM encoded CRL.
	* @param throw_on_unknown_critical_ should we throw new an exception
	* if an unknown CRL extension marked as critical is encountered.
	*/
	this(DataSource input, bool throw_on_unknown_critical_ = false)
	{
		m_throw_on_unknown_critical = throw_on_unknown_critical_;
		super(input, "X509 CRL/CRL");
		do_decode();
	}

	/**
	* Construct a CRL from a file containing the DER or PEM encoded CRL.
	* @param filename the name of the CRL file
	* @param throw_on_unknown_critical_ should we throw new an exception
	* if an unknown CRL extension marked as critical is encountered.
	*/
	this(in string filename,
				bool throw_on_unknown_critical_ = false)
	{
		m_throw_on_unknown_critical = throw_on_unknown_critical_;
		super(input, "CRL/X509 CRL");
		do_decode();
	}

	/**
	* Construct a CRL from a binary vector
	* @param vec the binary (DER) representation of the CRL
	* @param throw_on_unknown_critical_ should we throw new an exception
	* if an unknown CRL extension marked as critical is encountered.
	*/
	this(in Vector!ubyte vec,
				bool throw_on_unknown_critical_ = false)
	{
		m_throw_on_unknown_critical = throw_on_unknown_critical_;
		super(input, "CRL/X509 CRL");
		do_decode();
	}

private:

	/*
	* Decode the TBSCertList data
	*/
	void force_decode()
	{
		BER_Decoder tbs_crl = BER_Decoder(tbs_bits);
		
		size_t _version;
		tbs_crl.decode_optional(_version, INTEGER, ASN1_Tag.UNIVERSAL);
		
		if (_version != 0 && _version != 1)
			throw new X509_CRL_Error("Unknown X.509 CRL version " ~
			                         to!string(_version+1));
		
		Algorithm_Identifier sig_algo_inner;
		tbs_crl.decode(sig_algo_inner);
		
		if (sig_algo != sig_algo_inner)
			throw new X509_CRL_Error("Algorithm identifier mismatch");
		
		X509_DN dn_issuer;
		tbs_crl.decode(dn_issuer);
		m_info.add(dn_issuer.contents());
		
		X509_Time start, end;
		tbs_crl.decode(start).decode(end);
		m_info.add("X509.CRL.start", start.readable_string());
		m_info.add("X509.CRL.end", end.readable_string());
		
		BER_Object next = tbs_crl.get_next_object();
		
		if (next.type_tag == ASN1_Tag.SEQUENCE && next.class_tag == ASN1_Tag.CONSTRUCTED)
		{
			BER_Decoder cert_list = BER_Decoder(next.value);
			
			while (cert_list.more_items())
			{
				CRL_Entry entry = CRL_Entry(m_throw_on_unknown_critical);
				cert_list.decode(entry);
				m_revoked.push_back(entry);
			}
			next = tbs_crl.get_next_object();
		}
		
		if (next.type_tag == 0 &&
		    next.class_tag == ASN1_Tag(CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC))
		{
			BER_Decoder crl_options = BER_Decoder(next.value);
			
			Extensions extensions = Extensions(m_throw_on_unknown_critical);
			
			crl_options.decode(extensions).verify_end();
			
			extensions.contents_to(m_info, m_info);
			
			next = tbs_crl.get_next_object();
		}
		
		if (next.type_tag != ASN1_Tag.NO_OBJECT)
			throw new X509_CRL_Error("Unknown tag in CRL");
		
		tbs_crl.verify_end();
	}


	bool m_throw_on_unknown_critical;
	Vector!CRL_Entry m_revoked;
	Data_Store m_info;
}