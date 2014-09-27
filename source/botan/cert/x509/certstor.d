/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/certstor.h>

#if defined(BOTAN_HAS_BOOST_FILESYSTEM)
#include <boost/filesystem.hpp>
#endif
const X509_CRL* Certificate_Store::find_crl_for(in X509_Certificate) const
{
	return null;
}

void Certificate_Store_In_Memory::add_certificate(in X509_Certificate cert)
{
	for (size_t i = 0; i != m_certs.size(); ++i)
	{
		if (m_certs[i] == cert)
			return;
	}

	m_certs.push_back(cert);
}

Vector!( X509_DN ) Certificate_Store_In_Memory::all_subjects() const
{
	Vector!( X509_DN ) subjects;
	for (size_t i = 0; i != m_certs.size(); ++i)
		subjects.push_back(m_certs[i].subject_dn());
	return subjects;
}

namespace {

const X509_Certificate*
cert_search(in X509_DN subject_dn, in Vector!byte key_id,
				const Vector!( X509_Certificate )& certs)
{
	for (size_t i = 0; i != certs.size(); ++i)
	{
		// Only compare key ids if set in both call and in the cert
		if (key_id.size())
		{
			Vector!( byte ) skid = certs[i].subject_key_id();

			if (skid.size() && skid != key_id) // no match
				continue;
		}

		if (certs[i].subject_dn() == subject_dn)
			return &certs[i];
	}

	return null;
}

}

const X509_Certificate*
Certificate_Store_In_Memory::find_cert(in X509_DN subject_dn,
													in Vector!byte key_id) const
{
	return cert_search(subject_dn, key_id, m_certs);
}

void Certificate_Store_In_Memory::add_crl(in X509_CRL crl)
{
	X509_DN crl_issuer = crl.issuer_dn();

	for (size_t i = 0; i != m_crls.size(); ++i)
	{
		// Found an update of a previously existing one; replace it
		if (m_crls[i].issuer_dn() == crl_issuer)
		{
			if (m_crls[i].this_update() <= crl.this_update())
				m_crls[i] = crl;
			return;
		}
	}

	// Totally new CRL, add to the list
	m_crls.push_back(crl);
}

const X509_CRL* Certificate_Store_In_Memory::find_crl_for(in X509_Certificate subject) const
{
	in Vector!byte key_id = subject.authority_key_id();

	for (size_t i = 0; i != m_crls.size(); ++i)
	{
		// Only compare key ids if set in both call and in the CRL
		if (key_id.size())
		{
			Vector!( byte ) akid = m_crls[i].authority_key_id();

			if (akid.size() && akid != key_id) // no match
				continue;
		}

		if (m_crls[i].issuer_dn() == subject.issuer_dn())
			return &m_crls[i];
	}

	return null;
}

Certificate_Store_In_Memory::Certificate_Store_In_Memory(in string dir)
{
	if (dir == "")
		return;

#if defined(BOTAN_HAS_BOOST_FILESYSTEM)
	boost::filesystem::recursive_directory_iterator i(dir);
	boost::filesystem::recursive_directory_iterator end;

	while(i != end)
	{
		auto path = i->path();
		++i;

		try
		{
			if (boost::filesystem::is_regular_file(path))
				m_certs.push_back(X509_Certificate(path.native()));
		}
		catch(...) {}
	}
#else
	throw new Exception("Certificate_Store_In_Memory: FS access disabled");
#endif
}

const X509_Certificate*
Certificate_Store_Overlay::find_cert(in X509_DN subject_dn,
												 in Vector!byte key_id) const
{
	return cert_search(subject_dn, key_id, m_certs);
}

Vector!( X509_DN ) Certificate_Store_Overlay::all_subjects() const
{
	Vector!( X509_DN ) subjects;
	for (size_t i = 0; i != m_certs.size(); ++i)
		subjects.push_back(m_certs[i].subject_dn());
	return subjects;
}

}
