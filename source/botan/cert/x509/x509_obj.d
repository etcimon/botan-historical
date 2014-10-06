/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509_obj;
import botan.x509_key;
import botan.pubkey;
import botan.asn1.oid_lookup.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.parsing;
import botan.codec.pem.pem;
import algorithm;
/*
* Create a generic X.509 object
*/
X509_Object::X509_Object(DataSource stream, in string labels)
{
	init(stream, labels);
}

/*
* Create a generic X.509 object
*/
X509_Object::X509_Object(in string file, in string labels)
{
	DataSource_Stream stream = new DataSource_Stream(file, true);
	scope(exit) delete stream;
	init(stream, labels);
}

/*
* Create a generic X.509 object
*/
X509_Object::X509_Object(in Vector!ubyte vec, in string labels)
{
	DataSource_Memory stream = new DataSource_Memory(&vec[0], vec.size());
	scope(exit) delete stream;
	init(stream, labels);
}

/*
* Read a PEM or BER X.509 object
*/
void X509_Object::init(DataSource in, in string labels)
{
	PEM_labels_allowed = split_on(labels, '/');
	if (PEM_labels_allowed.size() < 1)
		throw new Invalid_Argument("Bad labels argument to X509_Object");

	PEM_label_pref = PEM_labels_allowed[0];
	std::sort(PEM_labels_allowed.begin(), PEM_labels_allowed.end());

	try {
		if (asn1_obj.maybe_BER(input) && !pem.matches(input))
		{
			BER_Decoder dec(input);
			decode_from(dec);
		}
		else
		{
			string got_label;
			DataSource_Memory ber(pem.decode(input, got_label));

			if (!std::binary_search(PEM_labels_allowed.begin(),
										  PEM_labels_allowed.end(), got_label))
				throw new Decoding_Error("Invalid PEM label: " ~ got_label);

			BER_Decoder dec(ber);
			decode_from(dec);
		}
	}
	catch(Decoding_Error e)
	{
		throw new Decoding_Error(PEM_label_pref ~ " decoding failed: " ~ e.what());
	}
}void X509_Object::encode_into(DER_Encoder& to) const
{
	to.start_cons(ASN1_Tag.SEQUENCE)
			.start_cons(ASN1_Tag.SEQUENCE)
				.raw_bytes(tbs_bits)
			.end_cons()
			.encode(sig_algo)
			.encode(sig, ASN1_Tag.BIT_STRING)
		.end_cons();
}

/*
* Read a BER encoded X.509 object
*/
void X509_Object::decode_from(BER_Decoder& from)
{
	from.start_cons(ASN1_Tag.SEQUENCE)
			.start_cons(ASN1_Tag.SEQUENCE)
				.raw_bytes(tbs_bits)
			.end_cons()
			.decode(sig_algo)
			.decode(sig, ASN1_Tag.BIT_STRING)
			.verify_end()
		.end_cons();
}

/*
* Return a BER encoded X.509 object
*/
Vector!ubyte X509_Object::BER_encode() const
{
	DER_Encoder der;
	encode_into(der);
	return der.get_contents_unlocked();
}

/*
* Return a PEM encoded X.509 object
*/
string X509_Object::PEM_encode() const
{
	return pem.encode(BER_encode(), PEM_label_pref);
}

/*
* Return the TBS data
*/
Vector!ubyte X509_Object::tbs_data() const
{
	return asn1_obj.put_in_sequence(tbs_bits);
}

/*
* Return the signature of this object
*/
Vector!ubyte X509_Object::signature() const
{
	return sig;
}

/*
* Return the algorithm used to sign this object
*/
AlgorithmIdentifier X509_Object::signature_algorithm() const
{
	return sig_algo;
}

/*
* Return the hash used in generating the signature
*/
string X509_Object::hash_used_for_signature() const
{
	Vector!string sig_info =
		split_on(oids.lookup(sig_algo.oid), '/');

	if (sig_info.size() != 2)
		throw new Internal_Error("Invalid name format found for " ~
									sig_algo.oid.as_string());

	Vector!string pad_and_hash =
		parse_algorithm_name(sig_info[1]);

	if (pad_and_hash.size() != 2)
		throw new Internal_Error("Invalid name format " ~ sig_info[1]);

	return pad_and_hash[1];
}

/*
* Check the signature on an object
*/
bool X509_Object::check_signature(const Public_Key pub_key) const
{
	Unique!const Public_Key key = pub_key;
	return check_signature(*key);
}

/*
* Check the signature on an object
*/
bool X509_Object::check_signature(in Public_Key pub_key) const
{
	try {
		Vector!string sig_info =
			split_on(oids.lookup(sig_algo.oid), '/');

		if (sig_info.size() != 2 || sig_info[0] != pub_key.algo_name())
			return false;

		string padding = sig_info[1];
		Signature_Format format =
			(pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;

		PK_Verifier verifier(pub_key, padding, format);

		return verifier.verify_message(tbs_data(), signature());
	}
	catch(std::exception& e)
	{
		return false;
	}
}

/*
* Apply the X.509 SIGNED macro
*/
Vector!ubyte X509_Object::make_signed(PK_Signer signer,
														  RandomNumberGenerator rng,
														  const AlgorithmIdentifier algo,
														  in SafeVector!ubyte tbs_bits)
{
	return DER_Encoder()
		.start_cons(ASN1_Tag.SEQUENCE)
			.raw_bytes(tbs_bits)
			.encode(algo)
			.encode(signer.sign_message(tbs_bits, rng), ASN1_Tag.BIT_STRING)
		.end_cons()
	.get_contents_unlocked();
}

/*
* Try to decode the actual information
*/
void X509_Object::do_decode()
{
	try {
		force_decode();
	}
	catch(Decoding_Error e)
	{
		throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~
									e.what() ~ ")");
	}
	catch(Invalid_Argument& e)
	{
		throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~
									e.what() ~ ")");
	}
}

}
