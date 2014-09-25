/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_OBJECT_H__
#define BOTAN_X509_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/pipe.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <vector>

namespace Botan {

/**
* This class represents abstract X.509 signed objects as
* in the X.500 SIGNED macro
*/
class X509_Object : public ASN1_Object
	{
	public:
		/**
		* The underlying data that is to be or was signed
		* @return data that is or was signed
		*/
		std::vector<byte> tbs_data() const;

		/**
		* @return signature on tbs_data()
		*/
		std::vector<byte> signature() const;

		/**
		* @return signature algorithm that was used to generate signature
		*/
		AlgorithmIdentifier signature_algorithm() const;

		/**
		* @return hash algorithm that was used to generate signature
		*/
		string hash_used_for_signature() const;

		/**
		* Create a signed X509 object.
		* @param signer the signer used to sign the object
		* @param rng the random number generator to use
		* @param alg_id the algorithm identifier of the signature scheme
		* @param tbs the tbs bits to be signed
		* @return signed X509 object
		*/
		static std::vector<byte> make_signed(class PK_Signer* signer,
														 RandomNumberGenerator& rng,
														 const AlgorithmIdentifier& alg_id,
														 in SafeArray!byte tbs);

		/**
		* Check the signature on this data
		* @param key the public key purportedly used to sign this data
		* @return true if the signature is valid, otherwise false
		*/
		bool check_signature(const Public_Key& key) const;

		/**
		* Check the signature on this data
		* @param key the public key purportedly used to sign this data
		*		  the pointer will be deleted after use
		* @return true if the signature is valid, otherwise false
		*/
		bool check_signature(const Public_Key* key) const;

		void encode_into(class DER_Encoder& to) const override;

		void decode_from(class BER_Decoder& from) override;

		/**
		* @return BER encoding of this
		*/
		std::vector<byte> BER_encode() const;

		/**
		* @return PEM encoding of this
		*/
		string PEM_encode() const;

		abstract ~X509_Object() {}
	protected:
		X509_Object(DataSource& src, in string pem_labels);
		X509_Object(in string file, in string pem_labels);
		X509_Object(in Array!byte vec, in string labels);

		void do_decode();
		X509_Object() {}
		AlgorithmIdentifier sig_algo;
		std::vector<byte> tbs_bits, sig;
	private:
		abstract void force_decode() = 0;
		void init(DataSource&, in string);

		std::vector<string> PEM_labels_allowed;
		string PEM_label_pref;
	};

}

#endif
