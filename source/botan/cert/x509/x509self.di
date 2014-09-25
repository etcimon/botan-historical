/*
* X.509 Self-Signed Certificate
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/pkcs10.h>
#include <botan/asn1_time.h>
/**
* Options for X.509 certificates.
*/
class X509_Cert_Options
{
	public:
		/**
		* the subject common name
		*/
		string common_name;

		/**
		* the subject counry
		*/
		string country;

		/**
		* the subject organization
		*/
		string organization;

		/**
		* the subject organizational unit
		*/
		string org_unit;

		/**
		* the subject locality
		*/
		string locality;

		/**
		* the subject state
		*/
		string state;

		/**
		* the subject serial number
		*/
		string serial_number;

		/**
		* the subject email adress
		*/
		string email;

		/**
		* the subject URI
		*/
		string uri;

		/**
		* the subject IPv4 address
		*/
		string ip;

		/**
		* the subject DNS
		*/
		string dns;

		/**
		* the subject XMPP
		*/
		string xmpp;

		/**
		* the subject challenge password
		*/
		string challenge;

		/**
		* the subject notBefore
		*/
		X509_Time start;
		/**
		* the subject notAfter
		*/
		X509_Time end;

		/**
		* Indicates whether the certificate request
		*/
		bool is_CA;

		/**
		* Indicates the BasicConstraints path limit
		*/
		size_t path_limit;

		/**
		* The key constraints for the subject public key
		*/
		Key_Constraints constraints;

		/**
		* The key extended constraints for the subject public key
		*/
		std::vector<OID> ex_constraints;

		/**
		* Check the options set in this object for validity.
		*/
		void sanity_check() const;

		/**
		* Mark the certificate as a CA certificate and set the path limit.
		* @param limit the path limit to be set in the BasicConstraints extension.
		*/
		void CA_key(size_t limit = 1);

		/**
		* Set the notBefore of the certificate.
		* @param time the notBefore value of the certificate
		*/
		void not_before(in string time);

		/**
		* Set the notAfter of the certificate.
		* @param time the notAfter value of the certificate
		*/
		void not_after(in string time);

		/**
		* Add the key constraints of the KeyUsage extension.
		* @param constr the constraints to set
		*/
		void add_constraints(Key_Constraints constr);

		/**
		* Add constraints to the ExtendedKeyUsage extension.
		* @param oid the oid to add
		*/
		void add_ex_constraint(const OID& oid);

		/**
		* Add constraints to the ExtendedKeyUsage extension.
		* @param name the name to look up the oid to add
		*/
		void add_ex_constraint(in string name);

		/**
		* Construct a new options object
		* @param opts define the common name of this object. An example for this
		* parameter would be "common_name/country/organization/organizational_unit".
		* @param expire_time the expiration time (from the current clock in seconds)
		*/
		X509_Cert_Options(in string opts = "",
								u32bit expire_time = 365 * 24 * 60 * 60);
};

namespace X509 {

/**
* Create a self-signed X.509 certificate.
* @param opts the options defining the certificate to create
* @param key the private key used for signing, i.e. the key
* associated with this self-signed certificate
* @param hash_fn the hash function to use
* @param rng the rng to use
* @return newly created self-signed certificate
*/
X509_Certificate
create_self_signed_cert(const X509_Cert_Options& opts,
								in Private_Key key,
								in string hash_fn,
								RandomNumberGenerator& rng);

/**
* Create a PKCS#10 certificate request.
* @param opts the options defining the request to create
* @param key the key used to sign this request
* @param rng the rng to use
* @param hash_fn the hash function to use
* @return newly created PKCS#10 request
*/
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
													  in Private_Key key,
													  in string hash_fn,
													  RandomNumberGenerator& rng);

}