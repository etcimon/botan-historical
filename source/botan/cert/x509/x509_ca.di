/*
* X.509 Certificate Authority
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.x509cert;
import botan.x509_crl;
import botan.x509_ext;
import botan.pkcs8;
import botan.cert.x509.pkcs10;
import botan.pubkey;
/**
* This class represents X.509 Certificate Authorities (CAs).
*/
class X509_CA
{
	public:

		/**
		* Sign a PKCS#10 Request.
		* @param req the request to sign
		* @param rng the rng to use
		* @param not_before the starting time for the certificate
		* @param not_after the expiration time for the certificate
		* @return resulting certificate
		*/
		X509_Certificate sign_request(in PKCS10_Request req,
												RandomNumberGenerator rng,
												const X509_Time& not_before,
												const X509_Time& not_after);

		/**
		* Get the certificate of this CA.
		* @return CA certificate
		*/
		X509_Certificate ca_certificate() const;

		/**
		* Create a new and empty CRL for this CA.
		* @param rng the random number generator to use
		* @param next_update the time to set in next update in seconds
		* as the offset from the current time
		* @return new CRL
		*/
		X509_CRL new_crl(RandomNumberGenerator rng,
							  uint next_update = 0) const;

		/**
		* Create a new CRL by with additional entries.
		* @param last_crl the last CRL of this CA to add the new entries to
		* @param new_entries contains the new CRL entries to be added to the CRL
		* @param rng the random number generator to use
		* @param next_update the time to set in next update in seconds
		* as the offset from the current time
		*/
		X509_CRL update_crl(in X509_CRL last_crl,
								  const Vector!( CRL_Entry )& new_entries,
								  RandomNumberGenerator rng,
								  uint next_update = 0) const;

		/**
		* Interface for creating new certificates
		* @param signer a signing object
		* @param rng a random number generator
		* @param sig_algo the signature algorithm identifier
		* @param pub_key the serialized public key
		* @param not_before the start time of the certificate
		* @param not_after the end time of the certificate
		* @param issuer_dn the DN of the issuer
		* @param subject_dn the DN of the subject
		* @param extensions an optional list of certificate extensions
		* @returns newly minted certificate
		*/
		static X509_Certificate make_cert(PK_Signer* signer,
													 RandomNumberGenerator rng,
													 const AlgorithmIdentifier& sig_algo,
													 in Vector!ubyte pub_key,
													 const X509_Time& not_before,
													 const X509_Time& not_after,
													 const X509_DN& issuer_dn,
													 const X509_DN& subject_dn,
													 const Extensions& extensions);

		/**
		* Create a new CA object.
		* @param ca_certificate the certificate of the CA
		* @param key the private key of the CA
		* @param hash_fn name of a hash function to use for signing
		*/
		X509_CA(in X509_Certificate ca_certificate,
				  in Private_Key key,
				  in string hash_fn);

		X509_CA(in X509_CA);
		X509_CA& operator=(in X509_CA);

		~this();
	private:
		X509_CRL make_crl(in Vector!( CRL_Entry ) entries,
								uint crl_number, uint next_update,
								RandomNumberGenerator rng) const;

		AlgorithmIdentifier ca_sig_algo;
		X509_Certificate cert;
		PK_Signer* signer;
};

/**
* Choose the default signature format for a certain public key signature
* scheme.
* @param key will be the key to choose a padding scheme for
* @param hash_fn is the desired hash function
* @param alg_id will be set to the chosen scheme
* @return A PK_Signer object for generating signatures
*/
PK_Signer* choose_sig_format(in Private_Key key,
													in string hash_fn,
													AlgorithmIdentifier& alg_id);