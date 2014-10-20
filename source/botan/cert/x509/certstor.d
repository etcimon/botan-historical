/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.certstor;

import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import std.file;

/**
* Certificate Store Interface
*/
class Certificate_Store
{
public:
	~this() {}

	/**
	* Subject DN and (optionally) key identifier
	*/
	abstract const X509_Certificate*
		find_cert(in X509_DN subject_dn, in Vector!ubyte key_id) const;

	abstract const X509_CRL* find_crl_for(in X509_Certificate subject) const
	{
		return null;
	}


	bool certificate_known(in X509_Certificate cert) const
	{
		return find_cert(cert.subject_dn(), cert.subject_key_id());
	}

	// remove this (used by TLS::Server)
	abstract Vector!( X509_DN ) all_subjects() const;
};

/**
* In Memory Certificate Store
*/
final class Certificate_Store_In_Memory : Certificate_Store
{
public:
	/**
	* Attempt to parse all files in dir (including subdirectories)
	* as certificates. Ignores errors.
	*/
	this(in string dir)
	{
		if (dir == "")
			return;
		foreach(string name; dirEntries(dir, SpanMode.breadth)) {
			if (isFile(name))
				m_certs.push_back(X509_Certificate(name));
		}
	}

	this() {}

	void add_certificate(in X509_Certificate cert)
	{
		for (size_t i = 0; i != m_certs.length; ++i)
		{
			if (m_certs[i] == cert)
				return;
		}
		
		m_certs.push_back(cert);
	}

	void add_crl(in X509_CRL crl);

	Vector!( X509_DN ) all_subjects() const
	{
		Vector!( X509_DN ) subjects;
		for (size_t i = 0; i != m_certs.length; ++i)
			subjects.push_back(m_certs[i].subject_dn());
		return subjects;
	}

	const X509_Certificate*
		find_cert(in X509_DN subject_dn,
		          in Vector!ubyte key_id) const
	{
		return cert_search(subject_dn, key_id, m_certs);
	}

	void add_crl(in X509_CRL crl)
	{
		X509_DN crl_issuer = crl.issuer_dn();
		
		for (size_t i = 0; i != m_crls.length; ++i)
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

	const X509_CRL* find_crl_for(in X509_Certificate subject) const
	{
		const Vector!ubyte key_id = subject.authority_key_id();
		
		for (size_t i = 0; i != m_crls.length; ++i)
		{
			// Only compare key ids if set in both call and in the CRL
			if (key_id.length)
			{
				Vector!ubyte akid = m_crls[i].authority_key_id();
				
				if (akid.length && akid != key_id) // no match
					continue;
			}
			
			if (m_crls[i].issuer_dn() == subject.issuer_dn())
				return &m_crls[i];
		}
		
		return null;
	}

private:
	// TODO: Add indexing on the DN and key id to avoid linear search
	Vector!( X509_Certificate ) m_certs;
	Vector!( X509_CRL ) m_crls;
};

final class Certificate_Store_Overlay : Certificate_Store
{
public:
	this(in Vector!( X509_Certificate ) certs)
	{
		m_certs = certs;
	}

	Vector!( X509_DN ) all_subjects() const
	{
		Vector!( X509_DN ) subjects;
		for (size_t i = 0; i != m_certs.length; ++i)
			subjects.push_back(m_certs[i].subject_dn());
		return subjects;
	}

	const X509_Certificate*
		find_cert(in X509_DN subject_dn,
		          in Vector!ubyte key_id) const
	{
		return cert_search(subject_dn, key_id, m_certs);
	}
private:
	const Vector!( X509_Certificate ) m_certs;
};

const X509_Certificate*
	cert_search(in X509_DN subject_dn, in Vector!ubyte key_id,
	            const ref Vector!( X509_Certificate ) certs)
{
	for (size_t i = 0; i != certs.length; ++i)
	{
		// Only compare key ids if set in both call and in the cert
		if (key_id.length)
		{
			Vector!ubyte skid = certs[i].subject_key_id();
			
			if (skid.length && skid != key_id) // no match
				continue;
		}
		
		if (certs[i].subject_dn() == subject_dn)
			return &certs[i];
	}
	
	return null;
}
