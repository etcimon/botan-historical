/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CREDENTIALS_MANAGER_H__
#define BOTAN_CREDENTIALS_MANAGER_H__

#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/symkey.h>
#include <string>

namespace Botan {

class BigInt;

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
		abstract ~Credentials_Manager() {}

		/**
		* Return a list of the certificates of CAs that we trust in this
		* type/context.
		*
		* @param type specifies the type of operation occuring
		*
		* @param context specifies a context relative to type. For instance
		*		  for type "tls-client", context specifies the servers name.
		*/
		abstract std::vector<Certificate_Store*> trusted_certificate_authorities(
			in string type,
			in string context);

		/**
		* Check the certificate chain is valid up to a trusted root, and
		* optionally (if hostname != "") that the hostname given is
		* consistent with the leaf certificate.
		*
		* This function should throw an exception derived from
		* std::exception with an informative what() result if the
		* certificate chain cannot be verified.

		* @param type specifies the type of operation occuring
		* @param hostname specifies the purported hostname
		* @param cert_chain specifies a certificate chain leading to a
		*		  trusted root CA certificate.
		*/
		abstract void verify_certificate_chain(
			in string type,
			in string hostname,
			const std::vector<X509_Certificate>& cert_chain);

		/**
		* Return a cert chain we can use, ordered from leaf to root,
		* or else an empty vector.
		*
		* It is assumed that the caller can get the private key of the
		* leaf with private_key_for
		*
		* @param cert_key_types specifies the key types desired ("RSA",
		*							  "DSA", "ECDSA", etc), or empty if there
		*							  is no preference by the caller.
		*
		* @param type specifies the type of operation occuring
		*
		* @param context specifies a context relative to type.
		*/
		abstract std::vector<X509_Certificate> cert_chain(
			const std::vector<string>& cert_key_types,
			in string type,
			in string context);

		/**
		* Return a cert chain we can use, ordered from leaf to root,
		* or else an empty vector.
		*
		* It is assumed that the caller can get the private key of the
		* leaf with private_key_for
		*
		* @param cert_key_type specifies the type of key requested
		*							 ("RSA", "DSA", "ECDSA", etc)
		*
		* @param type specifies the type of operation occuring
		*
		* @param context specifies a context relative to type.
		*/
		std::vector<X509_Certificate> cert_chain_single_type(
			in string cert_key_type,
			in string type,
			in string context);

		/**
		* @return private key associated with this certificate if we should
		*			use it with this context. cert was returned by cert_chain
		* @note this object should retain ownership of the returned key;
		*		 it should not be deleted by the caller.
		*/
		abstract Private_Key* private_key_for(const X509_Certificate& cert,
														 in string type,
														 in string context);

		/**
		* @param type specifies the type of operation occuring
		* @param context specifies a context relative to type.
		* @return true if we should attempt SRP authentication
		*/
		abstract bool attempt_srp(in string type,
										 in string context);

		/**
		* @param type specifies the type of operation occuring
		* @param context specifies a context relative to type.
		* @return identifier for client-side SRP auth, if available
					 for this type/context. Should return empty string
					 if password auth not desired/available.
		*/
		abstract string srp_identifier(in string type,
													  in string context);

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
													in string identifier);

		/**
		* Retrieve SRP verifier parameters
		*/
		abstract bool srp_verifier(in string type,
										  in string context,
										  in string identifier,
										  string& group_name,
										  BigInt& verifier,
										  std::vector<byte>& salt,
										  bool generate_fake_on_unknown);

		/**
		* @param type specifies the type of operation occuring
		* @param context specifies a context relative to type.
		* @return the PSK identity hint for this type/context
		*/
		abstract string psk_identity_hint(in string type,
														  in string context);

		/**
		* @param type specifies the type of operation occuring
		* @param context specifies a context relative to type.
		* @param identity_hint was passed by the server (but may be empty)
		* @return the PSK identity we want to use
		*/
		abstract string psk_identity(in string type,
													in string context,
													in string identity_hint);

		/**
		* @param type specifies the type of operation occuring
		* @param context specifies a context relative to type.
		* @param identity is a PSK identity previously returned by
					psk_identity for the same type and context.
		* @return the PSK used for identity, or throw an exception if no
		* key exists
		*/
		abstract SymmetricKey psk(in string type,
										 in string context,
										 in string identity);
	};

}

#endif
