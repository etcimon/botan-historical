/*
* PKCS #10
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.x509_obj;
import botan.x509_dn;
import botan.pkcs8;
import botan.datastor;
import botan.key_constraint;
import botan.asn1_attribute;
import botan.asn1_alt_name;
import vector;
/**
* PKCS #10 Certificate Request.
*/
class PKCS10_Request : public X509_Object
{
	public:
		/**
		* Get the subject public key.
		* @return subject public key
		*/
		Public_Key* subject_public_key() const;

		/**
		* Get the raw DER encoded public key.
		* @return raw DER encoded public key
		*/
		Vector!( byte ) raw_public_key() const;

		/**
		* Get the subject DN.
		* @return subject DN
		*/
		X509_DN subject_dn() const;

		/**
		* Get the subject alternative name.
		* @return subject alternative name.
		*/
		AlternativeName subject_alt_name() const;

		/**
		* Get the key constraints for the key associated with this
		* PKCS#10 object.
		* @return key constraints
		*/
		Key_Constraints constraints() const;

		/**
		* Get the extendend key constraints (if any).
		* @return extended key constraints
		*/
		Vector!( OID ) ex_constraints() const;

		/**
		* Find out whether this is a CA request.
		* @result true if it is a CA request, false otherwise.
		*/
		bool is_CA() const;

		/**
		* Return the constraint on the path length defined
		* in the BasicConstraints extension.
		* @return path limit
		*/
		uint path_limit() const;

		/**
		* Get the challenge password for this request
		* @return challenge password for this request
		*/
		string challenge_password() const;

		/**
		* Create a PKCS#10 Request from a data source.
		* @param source the data source providing the DER encoded request
		*/
		PKCS10_Request(DataSource& source);

		/**
		* Create a PKCS#10 Request from a file.
		* @param filename the name of the file containing the DER or PEM
		* encoded request file
		*/
		PKCS10_Request(in string filename);

		/**
		* Create a PKCS#10 Request from binary data.
		* @param vec a std::vector containing the DER value
		*/
		PKCS10_Request(in Vector!byte vec);
	private:
		void force_decode();
		void handle_attribute(in Attribute);

		Data_Store info;
};