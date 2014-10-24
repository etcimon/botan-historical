/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.credentials.credentials_manager;

import botan.cert.x509.x509cert;
import botan.cert.x509.certstor;
import botan.math.bigint.bigint;
import botan.pubkey.pk_keys;
import botan.algo_base.symkey;
import botan.credentials.credentials_manager;
import botan.cert.x509.x509path;
import string;

/**
* Interface for a credentials manager.
*
* A type is a fairly static value that represents the general nature
* of the transaction occuring. Currently used values are "tls-client"
* and "tls-server". Context represents a hostname, email address,
* username, or other identifier.
*/
class Credentials_Manager
{
public:
	~this() {}

	/**
	* Return a list of the certificates of CAs that we trust in this
	* type/context.
	*
	* @param type specifies the type of operation occuring
	*
	* @param context specifies a context relative to type. For instance
	*		  for type "tls-client", context specifies the servers name.
	*/
	abstract Vector!Certificate_Store trusted_certificate_authorities(
											in string type,
											in string context)
	{
		return Vector!Certificate_Store();
	}

	/**
	* Check the certificate chain is valid up to a trusted root, and
	* optionally (if hostname != "") that the hostname given is
	* consistent with the leaf certificate.
	*
	* This function should throw new an exception derived from
	* std::exception with an informative what() result if the
	* certificate chain cannot be verified.

	* @param type specifies the type of operation occuring
	* @param hostname specifies the purported hostname
	* @param cert_chain specifies a certificate chain leading to a
	*		  trusted root CA certificate.
	*/
	abstract void verify_certificate_chain(	in string type,
											in string purported_hostname,
											const ref Vector!X509_Certificate cert_chainput)
	{
		if (cert_chain.empty)
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

	/**
	* Return a cert chain we can use, ordered from leaf to root,
	* or else an empty vector.
	*
	* It is assumed that the caller can get the private key of the
	* leaf with Private_Key_for
	*
	* @param cert_key_types specifies the key types desired ("RSA",
	*							  "DSA", "ECDSA", etc), or empty if there
	*							  is no preference by the caller.
	*
	* @param type specifies the type of operation occuring
	*
	* @param context specifies a context relative to type.
	*/
	abstract Vector!X509_Certificate cert_chain( const ref Vector!string cert_key_types,
													in string type,
													in string context)
	{
		return Vector!X509_Certificate();
	}

	/**
	* Return a cert chain we can use, ordered from leaf to root,
	* or else an empty vector.
	*
	* It is assumed that the caller can get the private key of the
	* leaf with Private_Key_for
	*
	* @param cert_key_type specifies the type of key requested
	*							 ("RSA", "DSA", "ECDSA", etc)
	*
	* @param type specifies the type of operation occuring
	*
	* @param context specifies a context relative to type.
	*/
	abstract Vector!X509_Certificate cert_chain_single_type( in string cert_key_type,
																in string type,
																in string context)
	{
		Vector!string cert_types;
		cert_types.push_back(cert_key_type);
		return cert_chain(cert_types, type, context);
	}

	/**
	* @return private key associated with this certificate if we should
	*			use it with this context. cert was returned by cert_chain
	* @note this object should retain ownership of the returned key;
	*		 it should not be deleted by the caller.
	*/
	abstract Private_Key private_key_for( in X509_Certificate cert,
											 in string type,
											 in string context)
	{
		return null;
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @return true if we should attempt SRP authentication
	*/
	abstract bool attempt_srp(in string,
	                 			in string)
	{
		return false;
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @return identifier for client-side SRP auth, if available
				 for this type/context. Should return empty string
				 if password auth not desired/available.
	*/
	abstract string srp_identifier(	in string type,
										in string context)
	{
		return "";
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @param identifier specifies what identifier we want the
	*		  password for. This will be a value previously returned
	*		  by srp_identifier.
	* @return password for client-side SRP auth, if available
				 for this identifier/type/context.
	*/
	abstract string srp_password(in string type,
									in string context,
									in string identifier)
	{
		return "";
	}

	/**
	* Retrieve SRP verifier parameters
	*/
	abstract bool srp_verifier(in string type,
								  in string context,
								  in string identifier,
								  ref string group_name,
								  ref BigInt verifier,
								  ref Vector!ubyte salt,
								  bool generate_fake_on_unknown)
	{
		return false;
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @return the PSK identity hint for this type/context
	*/
	abstract string psk_identity_hint(in string type,
	                        			 in string context)
	{
		return "";
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @param identity_hint was passed by the server (but may be empty)
	* @return the PSK identity we want to use
	*/
	abstract string psk_identity(in string type,
				                    in string context,
				                    in string identity_hint)
	{
		return "";
	}

	/**
	* @param type specifies the type of operation occuring
	* @param context specifies a context relative to type.
	* @param identity is a PSK identity previously returned by
				psk_identity for the same type and context.
	* @return the PSK used for identity, or throw new an exception if no
	* key exists
	*/
	abstract SymmetricKey psk(in string type,
				                 in string context,
				                 in string identity)
	{
		throw new Internal_Error("No PSK set for identity " ~ identity);
	}
};

private:

bool cert_in_some_store(in Vector!Certificate_Store trusted_CAs,
                        const X509_Certificate trust_root)
{
	foreach (CAs; trusted_CAs)
		if (CAs.certificate_known(trust_root))
			return true;
	return false;
}
