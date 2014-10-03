/*
* OCSP subtypes
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.x509cert;
import botan.asn1_time;
import botan.bigint;
namespace OCSP {

class CertID : public ASN1_Object
{
	public:
		CertID() {}

		CertID(in X509_Certificate issuer,
				 const X509_Certificate& subject);

		bool is_id_for(in X509_Certificate issuer,
							const X509_Certificate& subject) const;

		void encode_into(class DER_Encoder& to) const override;

		void decode_from(class BER_Decoder& from) override;
	private:
		Vector!byte extract_key_bitstr(in X509_Certificate cert) const;

		AlgorithmIdentifier m_hash_id;
		Vector!byte m_issuer_dn_hash;
		Vector!byte m_issuer_key_hash;
		BigInt m_subject_serial;
};

class SingleResponse : public ASN1_Object
{
	public:
		const CertID& certid() const { return m_certid; }

		size_t cert_status() const { return m_cert_status; }

		X509_Time this_update() const { return m_thisupdate; }

		X509_Time next_update() const { return m_nextupdate; }

		void encode_into(class DER_Encoder& to) const override;

		void decode_from(class BER_Decoder& from) override;
	private:
		CertID m_certid;
		size_t m_cert_status = 2; // unknown
		X509_Time m_thisupdate;
		X509_Time m_nextupdate;
};

}