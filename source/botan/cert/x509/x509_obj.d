/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_obj;
import botan.asn1.asn1_obj;
import botan.pipe;
import botan.rng;
import botan.x509_key;
import botan.pubkey;
import botan.asn1.oid_lookup.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.parsing;
import botan.codec.pem;
import std.algorithm;
import vector;

/**
* This class represents abstract X.509 signed objects as
* in the X.500 SIGNED macro
*/
class X509_Object : ASN1_Object
{
public:
	/**
	* The underlying data that is to be or was signed
	* @return data that is or was signed
	*/
	Vector!ubyte tbs_data() const
	{
		return asn1_obj.put_in_sequence(tbs_bits);
	}

	/**
	* @return signature on tbs_data()
	*/
	Vector!ubyte signature() const
	{
		return sig;
	}

	/**
	* @return signature algorithm that was used to generate signature
	*/
	AlgorithmIdentifier signature_algorithm() const
	{
		return sig_algo;
	}

	/**
	* @return hash algorithm that was used to generate signature
	*/
	string hash_used_for_signature() const
	{
		Vector!string sig_info =
			std.algorithm.splitter(oids.lookup(sig_algo.oid), '/');
		
		if (sig_info.size() != 2)
			throw new Internal_Error("Invalid name format found for " ~
			                         sig_algo.oid.as_string());
		
		Vector!string pad_and_hash =
			parse_algorithm_name(sig_info[1]);
		
		if (pad_and_hash.size() != 2)
			throw new Internal_Error("Invalid name format " ~ sig_info[1]);
		
		return pad_and_hash[1];
	}


	/**
	* Create a signed X509 object.
	* @param signer the signer used to sign the object
	* @param rng the random number generator to use
	* @param alg_id the algorithm identifier of the signature scheme
	* @param tbs the tbs bits to be signed
	* @return signed X509 object
	*/
	static Vector!ubyte make_signed(PK_Signer signer,
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
	


	/**
	* Check the signature on this data
	* @param key the public key purportedly used to sign this data
	* @return true if the signature is valid, otherwise false
	*/
	bool check_signature(in Public_Key pub_key) const
	{
		try {
			Vector!string sig_info =
				std.algorithm.splitter(oids.lookup(sig_algo.oid), '/');
			
			if (sig_info.size() != 2 || sig_info[0] != pub_key.algo_name())
				return false;
			
			string padding = sig_info[1];
			Signature_Format format =
				(pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;
			
			PK_Verifier verifier = new PK_Verifier(pub_key, padding, format);
			scope(exit) delete verifier;
			return verifier.verify_message(tbs_data(), signature());
		}
		catch(Exception e)
		{
			return false;
		}
	}

	override void encode_into(DER_Encoder to) const
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
	override void decode_from(BER_Decoder from)
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


	/**
	* @return BER encoding of this
	*/
	Vector!ubyte BER_encode() const
	{
		DER_Encoder der = BER_Decoder();
		encode_into(der);
		return der.get_contents_unlocked();
	}


	/**
	* @return PEM encoding of this
	*/
	string PEM_encode() const
	{
		return pem.encode(BER_encode(), PEM_label_pref);
	}

	~this() {}
package:
	/*
	* Create a generic X.509 object
	*/
	this(DataSource stream, in string labels)
	{
		init(stream, labels);
	}

	/*
	* Create a generic X.509 object
	*/
	this(in string file, in string labels)
	{
		DataSource_Stream stream = new DataSource_Stream(file, true);
		scope(exit) delete stream;
		init(stream, labels);
	}

	/*
	* Create a generic X.509 object
	*/
	this(in Vector!ubyte vec, in string labels)
	{
		DataSource_Memory stream = new DataSource_Memory(&vec[0], vec.size());
		scope(exit) delete stream;
		init(stream, labels);
	}



	/*
	* Try to decode the actual information
	*/
	void do_decode()
	{
		try {
			force_decode();
		}
		catch(Decoding_Error e)
		{
			throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~
			                         e.what() ~ ")");
		}
		catch(Invalid_Argument e)
		{
			throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~
			                         e.what() ~ ")");
		}
	}
	this() {}
	AlgorithmIdentifier sig_algo;
	Vector!ubyte tbs_bits, sig;
private:
	abstract void force_decode();

	/*
	* Read a PEM or BER X.509 object
	*/
	void init(DataSource input, in string labels)
	{
		PEM_labels_allowed = std.algorithm.splitter(labels, '/');
		if (PEM_labels_allowed.size() < 1)
			throw new Invalid_Argument("Bad labels argument to X509_Object");
		
		PEM_label_pref = PEM_labels_allowed[0];
		std.algorithm.sort(PEM_labels_allowed.begin(), PEM_labels_allowed.end());
		
		try {
			if (asn1_obj.maybe_BER(input) && !pem.matches(input))
			{
				BER_Decoder dec = BER_Decoder(input);
				decode_from(dec);
			}
			else
			{
				string got_label;
				DataSource_Memory ber = new DataSource_Memory(pem.decode(input, got_label));
				scope(exit) delete ber;
				import std.algorithm : canFind;
				size_t idx = PEM_labels_allowed.canFind(got_label);
				if (idx == -1)
					throw new Decoding_Error("Invalid PEM label: " ~ got_label);
				
				BER_Decoder dec = BER_Decoder(ber);
				decode_from(dec);
			}
		}
		catch(Decoding_Error e)
		{
			throw new Decoding_Error(PEM_label_pref ~ " decoding failed: " ~ e.what());
		}
	}

	Vector!string PEM_labels_allowed;
	string PEM_label_pref;
};
