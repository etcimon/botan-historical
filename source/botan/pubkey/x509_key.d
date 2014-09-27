/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509_key;
import botan.der_enc;
import botan.ber_dec;
import botan.pem;
import botan.alg_id;
import botan.internal.pk_algs;
namespace X509 {

Vector!( byte ) BER_encode(in Public_Key key)
{
	return DER_Encoder()
			.start_cons(SEQUENCE)
				.encode(key.algorithm_identifier())
				.encode(key.x509_subject_public_key(), BIT_STRING)
			.end_cons()
		.get_contents_unlocked();
}

/*
* PEM encode a X.509 public key
*/
string PEM_encode(in Public_Key key)
{
	return PEM_Code::encode(X509::BER_encode(key),
									"PUBLIC KEY");
}

/*
* Extract a public key and return it
*/
Public_Key* load_key(DataSource& source)
{
	try {
		AlgorithmIdentifier alg_id;
		SafeVector!byte key_bits;

		if (ASN1::maybe_BER(source) && !PEM_Code::matches(source))
		{
			BER_Decoder(source)
				.start_cons(SEQUENCE)
				.decode(alg_id)
				.decode(key_bits, BIT_STRING)
				.verify_end()
			.end_cons();
		}
		else
		{
			DataSource_Memory ber(
				PEM_Code::decode_check_label(source, "PUBLIC KEY")
				);

			BER_Decoder(ber)
				.start_cons(SEQUENCE)
				.decode(alg_id)
				.decode(key_bits, BIT_STRING)
				.verify_end()
			.end_cons();
		}

		if (key_bits.empty())
			throw new Decoding_Error("X.509 public key decoding failed");

		return make_public_key(alg_id, key_bits);
	}
	catch(Decoding_Error)
	{
		throw new Decoding_Error("X.509 public key decoding failed");
	}
}

/*
* Extract a public key and return it
*/
Public_Key* load_key(in string fsname)
{
	DataSource_Stream source(fsname, true);
	return X509::load_key(source);
}

/*
* Extract a public key and return it
*/
Public_Key* load_key(in Vector!byte mem)
{
	DataSource_Memory source(mem);
	return X509::load_key(source);
}

/*
* Make a copy of this public key
*/
Public_Key* copy_key(in Public_Key key)
{
	DataSource_Memory source(PEM_encode(key));
	return X509::load_key(source);
}

}

}
