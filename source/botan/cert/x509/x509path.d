/*
* X.509 Certificate Path Validation
* (C) 2010,2011,2012,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509path;
import botan.cert.x509.ocsp;
import botan.http_util;
import botan.parsing;
import botan.pubkey;
import botan.asn1.oid_lookup.oids;
import algorithm;
import std.datetime;
import vector;
import set;

import iostream;
namespace {

const X509_Certificate*
find_issuing_cert(in X509_Certificate cert,
						Certificate_Store& end_certs,
						const Vector!( Certificate_Store* )& certstores)
{
	const X509_DN issuer_dn = cert.issuer_dn();
	const Vector!ubyte auth_key_id = cert.authority_key_id();

	if (const X509_Certificate* cert = end_certs.find_cert(issuer_dn, auth_key_id))
		return cert;

	for (size_t i = 0; i != certstores.size(); ++i)
	{
		if (const X509_Certificate* cert = certstores[i].find_cert(issuer_dn, auth_key_id))
			return cert;
	}

	return null;
}

const X509_CRL* find_crls_for(in X509_Certificate cert,
										const Vector!( Certificate_Store* )& certstores)
{
	for (size_t i = 0; i != certstores.size(); ++i)
	{
		if (const X509_CRL* crl = certstores[i].find_crl_for(cert))
			return crl;
	}

#if 0
	const string crl_url = cert.crl_distribution_point();
	if (crl_url != "")
	{
		std::cout << "Downloading CRL " << crl_url << "";
		auto http = HTTP::GET_sync(crl_url);

		std::cout << http.status_message() << "";

		http.throw_unless_ok();
		// check the mime type

		Unique!X509_CRL crl = new X509_CRL(http.body());

		return crl.release();
	}
#endif

	return null;
}

Vector!( std::set<Certificate_Status_Code )>
check_chain(in Vector!( X509_Certificate ) cert_path,
				const Path_Validation_Restrictions& restrictions,
				const Vector!( Certificate_Store* )& certstores)
{
	const std::set<string>& trusted_hashes = restrictions.trusted_hashes();

	const bool self_signed_ee_cert = (cert_path.size() == 1);

	X509_Time current_time(Clock.currTime());

	Vector!( std::future<ocsp.Response )> ocsp_responses;

	Vector!( std::set<Certificate_Status_Code )> cert_status(cert_path.size());

	for (size_t i = 0; i != cert_path.size(); ++i)
	{
		std::set<Certificate_Status_Code>& status = cert_status.at(i);

		const bool at_self_signed_root = (i == cert_path.size() - 1);

		const X509_Certificate& subject = cert_path[i];

		const X509_Certificate& issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];

		const Certificate_Store* trusted = certstores[0]; // fixme

		if (i == 0 || restrictions.ocsp_all_intermediates())
			ocsp_responses.push_back(
				std::async(std::launch::async,
							  ocsp.online_check, issuer, subject, trusted));

		// Check all certs for valid time range
		if (current_time < X509_Time(subject.start_time()))
			status.insert(Certificate_Status_Code.CERT_NOT_YET_VALID);

		if (current_time > X509_Time(subject.end_time()))
			status.insert(Certificate_Status_Code.CERT_HAS_EXPIRED);

		// Check issuer constraints

		// Don't require CA bit set on self-signed end entity cert
		if (!issuer.is_CA_cert() && !self_signed_ee_cert)
			status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CERT_ISSUER);

		if (issuer.path_limit() < i)
			status.insert(Certificate_Status_Code.CERT_CHAIN_TOO_LONG);

		Unique!Public_Key issuer_key = issuer.subject_public_key();

		if (subject.check_signature(*issuer_key) == false)
			status.insert(Certificate_Status_Code.SIGNATURE_ERROR);

		if (issuer_key.estimated_strength() < restrictions.minimum_key_strength())
			status.insert(Certificate_Status_Code.SIGNATURE_METHOD_TOO_WEAK);

		// Allow untrusted hashes on self-signed roots
		if (!trusted_hashes.empty() && !at_self_signed_root)
		{
			if (!trusted_hashes.count(subject.hash_used_for_signature()))
				status.insert(Certificate_Status_Code.UNTRUSTED_HASH);
		}
	}

	for (size_t i = 0; i != cert_path.size() - 1; ++i)
	{
		std::set<Certificate_Status_Code>& status = cert_status.at(i);

		const X509_Certificate& subject = cert_path.at(i);
		const X509_Certificate& ca = cert_path.at(i+1);

		if (i < ocsp_responses.size())
		{
			try
			{
				ocsp.Response ocsp = ocsp_responses[i].get();

				auto ocsp_status = ocsp.status_for(ca, subject);

				status.insert(ocsp_status);

				//std::cout << "OCSP status: " << Path_Validation_Result::status_string(ocsp_status) << "";

				// Either way we have a definitive answer, no need to check CRLs
				if (ocsp_status == Certificate_Status_Code.CERT_IS_REVOKED)
					return cert_status;
				else if (ocsp_status == Certificate_Status_Code.OCSP_RESPONSE_GOOD)
					continue;
			}
			catch(std::exception& e)
			{
				//std::cout << "OCSP error: " << e.what() << "";
			}
		}

		const X509_CRL* crl_p = find_crls_for(subject, certstores);

		if (!crl_p)
		{
			if (restrictions.require_revocation_information())
				status.insert(Certificate_Status_Code.NO_REVOCATION_DATA);
			continue;
		}

		const X509_CRL& crl = *crl_p;

		if (!ca.allowed_usage(CRL_SIGN))
			status.insert(Certificate_Status_Code.CA_CERT_NOT_FOR_CRL_ISSUER);

		if (current_time < X509_Time(crl.this_update()))
			status.insert(Certificate_Status_Code.CRL_NOT_YET_VALID);

		if (current_time > X509_Time(crl.next_update()))
			status.insert(Certificate_Status_Code.CRL_HAS_EXPIRED);

		if (crl.check_signature(ca.subject_public_key()) == false)
			status.insert(Certificate_Status_Code.CRL_BAD_SIGNATURE);

		if (crl.is_revoked(subject))
			status.insert(Certificate_Status_Code.CERT_IS_REVOKED);
	}

	if (self_signed_ee_cert)
		cert_status.back().insert(Certificate_Status_Code.CANNOT_ESTABLISH_TRUST);

	return cert_status;
}

}

Path_Validation_Result x509_path_validate(
	const Vector!( X509_Certificate )& end_certs,
	const Path_Validation_Restrictions& restrictions,
	const Vector!( Certificate_Store* )& certstores)
{
	if (end_certs.empty())
		throw new std::invalid_argument("x509_path_validate called with no subjects");

	Vector!( X509_Certificate ) cert_path;
	cert_path.push_back(end_certs[0]);

	Certificate_Store_Overlay extra(end_certs);

	// iterate until we reach a root or cannot find the issuer
	while(!cert_path.back().is_self_signed())
	{
		const X509_Certificate* cert = find_issuing_cert(cert_path.back(), extra, certstores);
		if (!cert)
			return Path_Validation_Result(Certificate_Status_Code.CERT_ISSUER_NOT_FOUND);

		cert_path.push_back(*cert);
	}

	return Path_Validation_Result(check_chain(cert_path, restrictions, certstores),
											std::move(cert_path));
}

Path_Validation_Result x509_path_validate(
	const X509_Certificate& end_cert,
	const Path_Validation_Restrictions& restrictions,
	const Vector!( Certificate_Store* )& certstores)
{
	Vector!( X509_Certificate ) certs;
	certs.push_back(end_cert);
	return x509_path_validate(certs, restrictions, certstores);
}

Path_Validation_Result x509_path_validate(
	const Vector!( X509_Certificate )& end_certs,
	const Path_Validation_Restrictions& restrictions,
	const Certificate_Store& store)
{
	Vector!( Certificate_Store* ) certstores;
	certstores.push_back(const_cast(<Certificate_Store*>)(&store));

	return x509_path_validate(end_certs, restrictions, certstores);
}

Path_Validation_Result x509_path_validate(
	const X509_Certificate& end_cert,
	const Path_Validation_Restrictions& restrictions,
	const Certificate_Store& store)
{
	Vector!( X509_Certificate ) certs;
	certs.push_back(end_cert);

	Vector!( Certificate_Store* ) certstores;
	certstores.push_back(const_cast(<Certificate_Store*>)(&store));

	return x509_path_validate(certs, restrictions, certstores);
}

Path_Validation_Restrictions::Path_Validation_Restrictions(bool require_rev,
																			  size_t key_strength,
																			  bool ocsp_all) :
	m_require_revocation_information(require_rev),
	m_ocsp_all_intermediates(ocsp_all),
	m_minimum_key_strength(key_strength)
{
	if (key_strength <= 80)
		m_trusted_hashes.insert("SHA-160");

	m_trusted_hashes.insert("SHA-224");
	m_trusted_hashes.insert("SHA-256");
	m_trusted_hashes.insert("SHA-384");
	m_trusted_hashes.insert("SHA-512");
}

Path_Validation_Result::Path_Validation_Result(Vector!( std::set<Certificate_Status_Code )> status,
															  Vector!( X509_Certificate )&& cert_chainput) :
	m_overall(Certificate_Status_Code.VERIFIED),
	m_all_status(status),
	m_cert_path(cert_chainput)
{
	// take the "worst" error as overall
	foreach (s; m_all_status)
	{
		if (!s.empty())
		{
			auto worst = *s.rbegin();
			// Leave OCSP confirmations on cert-level status only
			if (worst != Certificate_Status_Code.OCSP_RESPONSE_GOOD)
				m_overall = worst;
		}
	}
}

const X509_Certificate& Path_Validation_Result::trust_root() const
{
	return m_cert_path[m_cert_path.size()-1];
}

std::set<string> Path_Validation_Result::trusted_hashes() const
{
	std::set<string> hashes;
	for (size_t i = 0; i != m_cert_path.size(); ++i)
		hashes.insert(m_cert_path[i].hash_used_for_signature());
	return hashes;
}

bool Path_Validation_Result::successful_validation() const
{
	if (result() == Certificate_Status_Code.VERIFIED ||
		result() == Certificate_Status_Code.OCSP_RESPONSE_GOOD)
		return true;
	return false;
}

string Path_Validation_Result::result_string() const
{
	return status_string(result());
}

string Path_Validation_Result::status_string(Certificate_Status_Code code)
{
	switch(code)
	{
		case Certificate_Status_Code.VERIFIED:
			return "Verified";
		case Certificate_Status_Code.OCSP_RESPONSE_GOOD:
			return "OCSP response good";
		case Certificate_Status_Code.NO_REVOCATION_DATA:
			return "No revocation data";
		case Certificate_Status_Code.SIGNATURE_METHOD_TOO_WEAK:
			return "Signature method too weak";
		case Certificate_Status_Code.UNTRUSTED_HASH:
			return "Untrusted hash";

		case Certificate_Status_Code.CERT_NOT_YET_VALID:
			return "Certificate is not yet valid";
		case Certificate_Status_Code.CERT_HAS_EXPIRED:
			return "Certificate has expired";
		case Certificate_Status_Code.OCSP_NOT_YET_VALID:
			return "OCSP is not yet valid";
		case Certificate_Status_Code.OCSP_HAS_EXPIRED:
			return "OCSP has expired";
		case Certificate_Status_Code.CRL_NOT_YET_VALID:
			return "CRL is not yet valid";
		case Certificate_Status_Code.CRL_HAS_EXPIRED:
			return "CRL has expired";

		case Certificate_Status_Code.CERT_ISSUER_NOT_FOUND:
			return "Certificate issuer not found";
		case Certificate_Status_Code.CANNOT_ESTABLISH_TRUST:
			return "Cannot establish trust";

		case Certificate_Status_Code.POLICY_ERROR:
			return "Policy error";
		case Certificate_Status_Code.INVALID_USAGE:
			return "Invalid usage";
		case Certificate_Status_Code.CERT_CHAIN_TOO_LONG:
			return "Certificate chain too long";
		case Certificate_Status_Code.CA_CERT_NOT_FOR_CERT_ISSUER:
			return "CA certificate not allowed to issue certs";
		case Certificate_Status_Code.CA_CERT_NOT_FOR_CRL_ISSUER:
			return "CA certificate not allowed to issue CRLs";
		case Certificate_Status_Code.OCSP_CERT_NOT_LISTED:
			return "OCSP cert not listed";
		case Certificate_Status_Code.OCSP_BAD_STATUS:
			return "OCSP bad status";

		case Certificate_Status_Code.CERT_IS_REVOKED:
			return "Certificate is revoked";
		case Certificate_Status_Code.CRL_BAD_SIGNATURE:
			return "CRL bad signature";
		case Certificate_Status_Code.SIGNATURE_ERROR:
			return "Signature error";
		default:
			return "Unknown error";
	}
}

}
