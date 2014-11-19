/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.x509_key;

alias x509_key = botan.pubkey.x509_key;

public import botan.pubkey.pk_keys;
public import botan.asn1.alg_id;
public import botan.filters.pipe;
import botan.pubkey.x509_key;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.codec.pem;
import botan.asn1.alg_id;
import botan.pubkey.pk_algs;
import botan.utils.types;

// import string;
/**
* The two types of X509 encoding supported by Botan.
*/
enum X509_Encoding { RAW_BER, PEM }

/**
* BER encode a key
* @param key the public key to encode
* @return BER encoding of this key
*/
Vector!ubyte BER_encode(in Public_Key key)
{
	return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
			.encode(key.algorithm_identifier())
			.encode(key.x509_subject_public_key(), ASN1_Tag.BIT_STRING)
			.end_cons()
			.get_contents_unlocked();
}

/**
* PEM encode a public key into a string.
* @param key the key to encode
* @return PEM encoded key
*/
string PEM_encode(in Public_Key key)
{
	return PEM.encode(x509_key.BER_encode(key), "PUBLIC KEY");
}

/**
* Create a public key from a data source.
* @param source the source providing the DER or PEM encoded key
* @return new public key object
*/
Public_Key load_key(DataSource source)
{
	try {
		Algorithm_Identifier alg_id;
		Secure_Vector!ubyte key_bits;
		
		if (asn1_obj.maybe_BER(source) && !PEM.matches(source))
		{
			BER_Decoder(source)
					.start_cons(ASN1_Tag.SEQUENCE)
					.decode(alg_id)
					.decode(key_bits, ASN1_Tag.BIT_STRING)
					.verify_end()
					.end_cons();
		}
		else
		{
			auto ber = scoped!DataSource_Memory(PEM.decode_check_label(source, "PUBLIC KEY"));
			
			BER_Decoder(ber)
					.start_cons(ASN1_Tag.SEQUENCE)
					.decode(alg_id)
					.decode(key_bits, ASN1_Tag.BIT_STRING)
					.verify_end()
					.end_cons();
		}
		
		if (key_bits.empty)
			throw new Decoding_Error("X.509 public key decoding failed");
		
		return make_public_key(alg_id, key_bits);
	}
	catch(Decoding_Error)
	{
		throw new Decoding_Error("X.509 public key decoding failed");
	}
}

/**
* Create a public key from a file
* @param filename pathname to the file to load
* @return new public key object
*/
Public_Key load_key(in string filename)
{
	auto source = scoped!DataSource_Stream(filename, true);
	return x509_key.load_key(source);
}


/**
* Create a public key from a memory region.
* @param enc the memory region containing the DER or PEM encoded key
* @return new public key object
*/
Public_Key load_key(in Vector!ubyte enc)
{
	auto source = scoped!DataSource_Memory(enc);
	return x509_key.load_key(source);
}

/**
* Copy a key.
* @param key the public key to copy
* @return new public key object
*/
Public_Key copy_key(in Public_Key key)
{
	auto source = scoped!DataSource_Memory(PEM_encode(key));
	return x509_key.load_key(source);
}