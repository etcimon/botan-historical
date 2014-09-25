/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/x509cert.h>
#include <botan/x509_crl.h>
/**
* Certificate Store Interface
*/
class Certificate_Store
{
	public:
		abstract ~Certificate_Store() {}

		/**
		* Subject DN and (optionally) key identifier
		*/
		abstract const X509_Certificate*
			find_cert(in X509_DN subject_dn, in Vector!byte key_id) const = 0;

		abstract const X509_CRL* find_crl_for(in X509_Certificate subject) const;

		bool certificate_known(in X509_Certificate cert) const
		{
			return find_cert(cert.subject_dn(), cert.subject_key_id());
		}

		// remove this (used by TLS::Server)
		abstract Vector!( X509_DN ) all_subjects() const = 0;
};

/**
* In Memory Certificate Store
*/
class Certificate_Store_In_Memory : public Certificate_Store
{
	public:
		/**
		* Attempt to parse all files in dir (including subdirectories)
		* as certificates. Ignores errors.
		*/
		Certificate_Store_In_Memory(in string dir);

		Certificate_Store_In_Memory() {}

		void add_certificate(in X509_Certificate cert);

		void add_crl(in X509_CRL crl);

		Vector!( X509_DN ) all_subjects() const override;

		const X509_Certificate* find_cert(
			const X509_DN& subject_dn,
			in Vector!byte key_id) const override;

		const X509_CRL* find_crl_for(in X509_Certificate subject) const override;
	private:
		// TODO: Add indexing on the DN and key id to avoid linear search
		Vector!( X509_Certificate ) m_certs;
		Vector!( X509_CRL ) m_crls;
};

class Certificate_Store_Overlay : public Certificate_Store
{
	public:
		Certificate_Store_Overlay(in Vector!( X509_Certificate ) certs) :
			m_certs(certs) {}

		Vector!( X509_DN ) all_subjects() const override;

		const X509_Certificate* find_cert(
			const X509_DN& subject_dn,
			in Vector!byte key_id) const override;
	private:
		const Vector!( X509_Certificate )& m_certs;
};