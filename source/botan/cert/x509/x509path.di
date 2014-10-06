/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.cert.x509.cert_status;
import botan.cert.x509.x509cert;
import botan.cert.x509.certstor;
import set;
/**
* Specifies restrictions on the PKIX path validation
*/
class Path_Validation_Restrictions
{
	public:
		/**
		* @param require_rev if true, revocation information is required
		* @param minimum_key_strength is the minimum strength (in terms of
		*		  operations, eg 80 means 2^80) of a signature. Signatures
		*		  weaker than this are rejected. If more than 80, SHA-1
		*		  signatures are also rejected.
		*/
		Path_Validation_Restrictions(bool require_rev = false,
											  size_t minimum_key_strength = 80,
											  bool ocsp_all_intermediates = false);

		/**
		* @param require_rev if true, revocation information is required
		* @param minimum_key_strength is the minimum strength (in terms of
		*		  operations, eg 80 means 2^80) of a signature. Signatures
		*		  weaker than this are rejected.
		* @param trusted_hashes a set of trusted hashes. Any signatures
		*		  created using a hash other than one of these will be
		*		  rejected.
		*/
		Path_Validation_Restrictions(bool require_rev,
											  size_t minimum_key_strength,
											  bool ocsp_all_intermediates,
											  const std::set<string>& trusted_hashes) :
			m_require_revocation_information(require_rev),
			m_ocsp_all_intermediates(ocsp_all_intermediates),
			m_trusted_hashes(trusted_hashes),
			m_minimum_key_strength(minimum_key_strength) {}

		bool require_revocation_information() const
		{ return m_require_revocation_information; }

		bool ocsp_all_intermediates() const
		{ return m_ocsp_all_intermediates; }

		const std::set<string>& trusted_hashes() const
		{ return m_trusted_hashes; }

		size_t minimum_key_strength() const
		{ return m_minimum_key_strength; }

	private:
		bool m_require_revocation_information;
		bool m_ocsp_all_intermediates;
		std::set<string> m_trusted_hashes;
		size_t m_minimum_key_strength;
};

/**
* Represents the result of a PKIX path validation
*/
class Path_Validation_Result
{
	public:
		typedef Certificate_Status_Code Code;

		/**
		* @return the set of hash functions you are implicitly
		* trusting by trusting this result.
		*/
		std::set<string> trusted_hashes() const;

		/**
		* @return the trust root of the validation
		*/
		const X509_Certificate& trust_root() const;

		/**
		* @return the full path from subject to trust root
		*/
		const Vector!( X509_Certificate )& cert_path() const { return m_cert_path; }

		/**
		* @return true iff the validation was succesful
		*/
		bool successful_validation() const;

		/**
		* @return overall validation result code
		*/
		Certificate_Status_Code result() const { return m_overall; }

		/**
		* Return a set of status codes for each certificate in the chain
		*/
		const Vector!( std::set<Certificate_Status_Code )>& all_statuses() const
		{ return m_all_status; }

		/**
		* @return string representation of the validation result
		*/
		string result_string() const;

		static string status_string(Certificate_Status_Code code);

		Path_Validation_Result(Vector!( std::set<Certificate_Status_Code )> status,
									  Vector!( X509_Certificate )&& cert_chainput);

		Path_Validation_Result(Certificate_Status_Code status) : m_overall(status) {}

	private:
		friend Path_Validation_Result x509_path_validate(
			const Vector!( X509_Certificate )& end_certs,
			const Path_Validation_Restrictions& restrictions,
			const Vector!( Certificate_Store* )& certstores);

		Certificate_Status_Code m_overall;
		Vector!( std::set<Certificate_Status_Code )> m_all_status;
		Vector!( X509_Certificate ) m_cert_path;
};

/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(
	const Vector!( X509_Certificate )& end_certs,
	const Path_Validation_Restrictions& restrictions,
	const Vector!( Certificate_Store* )& certstores);

/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(
	const X509_Certificate& end_cert,
	const Path_Validation_Restrictions& restrictions,
	const Vector!( Certificate_Store* )& certstores);

/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(
	const X509_Certificate& end_cert,
	const Path_Validation_Restrictions& restrictions,
	const Certificate_Store& store);

/**
* PKIX Path Validation
*/
Path_Validation_Result x509_path_validate(
	const Vector!( X509_Certificate )& end_certs,
	const Path_Validation_Restrictions& restrictions,
	const Certificate_Store& store);