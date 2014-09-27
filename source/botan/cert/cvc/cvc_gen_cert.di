/*
* EAC1_1 general CVC
* (C) 2008 Falko Strenzke
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.eac_obj;
import botan.eac_asn_obj;
import botan.ecdsa;
import botan.pubkey;
/**
*  This class represents TR03110 (EAC) v1.1 generalized CV Certificates
*/
class EAC1_1_gen_CVC(Derived) : public EAC1_1_obj!Derived // CRTP continuation from EAC1_1_obj
{
		friend class EAC1_1_obj!EAC1_1_gen_CVC;

	public:

		/**
		* Get this certificates public key.
		* @result this certificates public key
		*/
		Public_Key* subject_public_key() const;

		/**
		* Find out whether this object is self signed.
		* @result true if this object is self signed
		*/
		bool is_self_signed() const;

		/**
		* Get the CHR of the certificate.
		* @result the CHR of the certificate
		*/
		ASN1_Chr get_chr() const {
			return m_chr;
		};

		/**
		* Put the DER encoded version of this object into a pipe. PEM
		* is not supported.
		* @param out the pipe to push the DER encoded version into
		* @param encoding the encoding to use. Must be DER.
		*/
		void encode(Pipe output, X509_Encoding encoding) const;

		/**
		* Get the to-be-signed (TBS) data of this object.
		* @result the TBS data of this object
		*/
		Vector!( byte ) tbs_data() const;

		/**
		* Build the DER encoded certifcate body of an object
		* @param tbs the data to be signed
		* @result the correctly encoded body of the object
		*/
		static Vector!( byte ) build_cert_body(in Vector!byte tbs);

		/**
		* Create a signed generalized CVC object.
		* @param signer the signer used to sign this object
		* @param tbs_bits the body the generalized CVC object to be signed
		* @param rng a random number generator
		* @result the DER encoded signed generalized CVC object
		*/
		static Vector!( byte ) make_signed(
			PK_Signer signer,
			in Vector!byte tbs_bits,
			RandomNumberGenerator rng);

		EAC1_1_gen_CVC() { m_pk = 0; }

		~this()
		{ delete m_pk; }

	protected:
		ECDSA_PublicKey* m_pk;
		ASN1_Chr m_chr;
		bool self_signed;

		static void decode_info(DataSource source,
										Vector!( byte ) res_tbs_bits,
										ECDSA_Signature res_sig);

};

template<typename Derived> ASN1_Chr EAC1_1_gen_CVC<Derived>::

template<typename Derived> bool EAC1_1_gen_CVC<Derived>::is_self_signed() const
{
	return self_signed;
}

template<typename Derived>
Vector!( byte ) EAC1_1_gen_CVC<Derived>::make_signed(
	PK_Signer signer,
	in Vector!byte tbs_bits,
	RandomNumberGenerator rng) // static
{
	const auto concat_sig = signer.sign_message(tbs_bits, rng);

	return DER_Encoder()
		.start_cons(ASN1_Tag(33), APPLICATION)
		.raw_bytes(tbs_bits)
		.encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
		.end_cons()
		.get_contents_unlocked();
}

template<typename Derived>
Public_Key* EAC1_1_gen_CVC<Derived>::subject_public_key() const
{
	return new ECDSA_PublicKey(m_pk);
}

template<typename Derived> Vector!( byte ) EAC1_1_gen_CVC<Derived>::build_cert_body(in Vector!byte tbs)
{
	return DER_Encoder()
		.start_cons(ASN1_Tag(78), APPLICATION)
		.raw_bytes(tbs)
		.end_cons().get_contents_unlocked();
}

template<typename Derived> Vector!( byte ) EAC1_1_gen_CVC<Derived>::tbs_data() const
{
	return build_cert_body(EAC1_1_obj<Derived>::tbs_bits);
}

template<typename Derived> void EAC1_1_gen_CVC<Derived>::encode(Pipe output, X509_Encoding encoding) const
{
	Vector!( byte ) concat_sig(EAC1_1_obj<Derived>::m_sig.get_concatenation());
	Vector!( byte ) der = DER_Encoder()
		.start_cons(ASN1_Tag(33), APPLICATION)
		.start_cons(ASN1_Tag(78), APPLICATION)
		.raw_bytes(EAC1_1_obj<Derived>::tbs_bits)
		.end_cons()
		.encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
		.end_cons()
		.get_contents_unlocked();

	if (encoding == PEM)
		throw new Invalid_Argument("EAC1_1_gen_CVC::encode() cannot PEM encode an EAC object");
	else
		output.write(der);
}

template<typename Derived>
void EAC1_1_gen_CVC<Derived>::decode_info(
	DataSource source,
	Vector!( byte ) res_tbs_bits,
	ECDSA_Signature res_sig)
{
	Vector!( byte ) concat_sig;
	BER_Decoder(source)
		.start_cons(ASN1_Tag(33))
		.start_cons(ASN1_Tag(78))
		.raw_bytes(res_tbs_bits)
		.end_cons()
		.decode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
		.end_cons();
	res_sig = decode_concatenation(concat_sig);
}

