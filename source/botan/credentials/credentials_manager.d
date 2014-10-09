/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.credentials_manager;
import botan.cert.x509.x509path;
string Credentials_Manager::psk_identity_hint(in string,
																	in string)
{
	return "";
}

string Credentials_Manager::psk_identity(in string,
															 in string,
															 in string)
{
	return "";
}

SymmetricKey Credentials_Manager::psk(in string,
												  in string,
												  in string identity)
{
	throw new Internal_Error("No PSK set for identity " ~ identity);
}

bool Credentials_Manager::attempt_srp(in string,
												  in string)
{
	return false;
}

string Credentials_Manager::srp_identifier(in string,
																in string)
{
	return "";
}

string Credentials_Manager::srp_password(in string,
															 in string,
															 in string)
{
	return "";
}

bool Credentials_Manager::srp_verifier(in string,
													in string,
													in string,
													string&,
													ref BigInt,
													Vector!ubyte&,
													bool)
{
	return false;
}

Vector!( X509_Certificate ) Credentials_Manager::cert_chain(
	const Vector!string&,
	in string,
	in string)
{
	return Vector!( X509_Certificate )();
}

Vector!( X509_Certificate ) Credentials_Manager::cert_chain_single_type(
	in string cert_key_type,
	in string type,
	in string context)
{
	Vector!string cert_types;
	cert_types.push_back(cert_key_type);
	return cert_chain(cert_types, type, context);
}

Private_Key Credentials_Manager::Private_Key_for(in X509_Certificate,
																  in string,
																  in string)
{
	return null;
}

Vector!( Certificate_Store* )
Credentials_Manager::trusted_certificate_authorities(
	in string,
	in string)
{
	return Vector!( Certificate_Store* )();
}

namespace {

bool cert_in_some_store(in Vector!( Certificate_Store* ) trusted_CAs,
								const X509_Certificate& trust_root)
{
	foreach (CAs; trusted_CAs)
		if (CAs.certificate_known(trust_root))
			return true;
	return false;
}

}

void Credentials_Manager::verify_certificate_chain(
	in string type,
	in string purported_hostname,
	const Vector!( X509_Certificate )& cert_chainput)
{
	if (cert_chain.empty())
		throw new Invalid_Argument("Certificate chain was empty");

	auto trusted_CAs = trusted_certificate_authorities(type, purported_hostname);

	Path_Validation_Restrictions restrictions;

	auto result = x509_path_validate(cert_chain,
												restrictions,
												trusted_CAs);

	if (!result.successful_validation())
		throw new Exception("Certificate validation failure: " ~ result.result_string());

	if (!cert_in_some_store(trusted_CAs, result.trust_root()))
		throw new Exception("Certificate chain roots in unknown/untrusted CA");

	if (purported_hostname != "" && !cert_chainput[0].matches_dns_name(purported_hostname))
		throw new Exception("Certificate did not match hostname");
}

}
