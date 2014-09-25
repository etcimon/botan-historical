/*
* OCSP
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/cert_status.h>
#include <botan/ocsp_types.h>
class Certificate_Store;

namespace OCSP {

class Request
{
	public:
		Request(in X509_Certificate issuer_cert,
				  const X509_Certificate& subject_cert) :
			m_issuer(issuer_cert),
			m_subject(subject_cert)
		{}

		Vector!( byte ) BER_encode() const;

		string base64_encode() const;

		const X509_Certificate& issuer() const { return m_issuer; }

		const X509_Certificate& subject() const { return m_subject; }
	private:
		X509_Certificate m_issuer, m_subject;
};

class Response
{
	public:
		Response() {}

		Response(in Certificate_Store trusted_roots,
					in Vector!byte response);

		Certificate_Status_Code status_for(in X509_Certificate issuer,
															  const X509_Certificate& subject) const;

	private:
		Vector!( SingleResponse ) m_responses;
};

Response online_check(in X509_Certificate issuer,
										  const X509_Certificate& subject,
										  const Certificate_Store* trusted_roots);

}