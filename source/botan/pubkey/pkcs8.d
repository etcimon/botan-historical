/*
* PKCS #8
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pkcs8;
import botan.get_pbe;
import botan.der_enc;
import botan.ber_dec;
import botan.alg_id;
import botan.oids;
import botan.pem;
import botan.internal.pk_algs;
namespace PKCS8 {

namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
SafeVector!byte PKCS8_extract(DataSource& source,
											 AlgorithmIdentifier& pbe_alg_id)
{
	SafeVector!byte key_data;

	BER_Decoder(source)
		.start_cons(SEQUENCE)
			.decode(pbe_alg_id)
			.decode(key_data, OCTET_STRING)
		.verify_end();

	return key_data;
}

/*
* PEM decode and/or decrypt a private key
*/
SafeVector!byte PKCS8_decode(
	DataSource& source,
	std::function<std::pair<bool,string> ()> get_passphrase,
	AlgorithmIdentifier& pk_alg_id)
{
	AlgorithmIdentifier pbe_alg_id;
	SafeVector!byte key_data, key;
	bool is_encrypted = true;

	try {
		if (ASN1::maybe_BER(source) && !PEM_Code::matches(source))
			key_data = PKCS8_extract(source, pbe_alg_id);
		else
		{
			string label;
			key_data = PEM_Code::decode(source, label);
			if (label == "PRIVATE KEY")
				is_encrypted = false;
			else if (label == "ENCRYPTED PRIVATE KEY")
			{
				DataSource_Memory key_source(key_data);
				key_data = PKCS8_extract(key_source, pbe_alg_id);
			}
			else
				throw new PKCS8_Exception("Unknown PEM label " + label);
		}

		if (key_data.empty())
			throw new PKCS8_Exception("No key data found");
	}
	catch(Decoding_Error& e)
	{
		throw new Decoding_Error("PKCS #8 private key decoding failed: " + string(e.what()));
	}

	if (!is_encrypted)
		key = key_data;

	const size_t MAX_TRIES = 3;

	size_t tries = 0;
	while(true)
	{
		try {
			if (MAX_TRIES && tries >= MAX_TRIES)
				break;

			if (is_encrypted)
			{
				Pair!(bool, string) pass = get_passphrase();

				if (pass.first == false)
					break;

				Pipe decryptor(get_pbe(pbe_alg_id.oid, pbe_alg_id.parameters, pass.second));

				decryptor.process_msg(key_data);
				key = decryptor.read_all();
			}

			BER_Decoder(key)
				.start_cons(SEQUENCE)
					.decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
					.decode(pk_alg_id)
					.decode(key, OCTET_STRING)
					.discard_remaining()
				.end_cons();

			break;
		}
		catch(Decoding_Error)
		{
			++tries;
		}
	}

	if (key.empty())
		throw new Decoding_Error("PKCS #8 private key decoding failed");
	return key;
}

}

/*
* BER encode a PKCS #8 private key, unencrypted
*/
SafeVector!byte BER_encode(in Private_Key key)
{
	const size_t PKCS8_VERSION = 0;

	return DER_Encoder()
			.start_cons(SEQUENCE)
				.encode(PKCS8_VERSION)
				.encode(key.pkcs8_algorithm_identifier())
				.encode(key.pkcs8_Private_Key(), OCTET_STRING)
			.end_cons()
		.get_contents();
}

/*
* PEM encode a PKCS #8 private key, unencrypted
*/
string PEM_encode(in Private_Key key)
{
	return PEM_Code::encode(PKCS8::BER_encode(key), "PRIVATE KEY");
}

/*
* BER encode a PKCS #8 private key, encrypted
*/
Vector!( byte ) BER_encode(in Private_Key key,
									  RandomNumberGenerator& rng,
									  in string pass,
									  std::chrono::milliseconds msec,
									  in string pbe_algo)
{
	const string DEFAULT_PBE = "PBE-PKCS5v20(SHA-1,AES-256/CBC)";

	Unique!PBE pbe(
		get_pbe(((pbe_algo != "") ? pbe_algo : DEFAULT_PBE),
				  pass,
				  msec,
				  rng));

	AlgorithmIdentifier pbe_algid(pbe->get_oid(), pbe->encode_params());

	Pipe key_encrytor(pbe.release());
	key_encrytor.process_msg(PKCS8::BER_encode(key));

	return DER_Encoder()
			.start_cons(SEQUENCE)
				.encode(pbe_algid)
				.encode(key_encrytor.read_all(), OCTET_STRING)
			.end_cons()
		.get_contents_unlocked();
}

/*
* PEM encode a PKCS #8 private key, encrypted
*/
string PEM_encode(in Private_Key key,
							  RandomNumberGenerator& rng,
							  in string pass,
							  std::chrono::milliseconds msec,
							  in string pbe_algo)
{
	if (pass == "")
		return PEM_encode(key);

	return PEM_Code::encode(PKCS8::BER_encode(key, rng, pass, msec, pbe_algo),
									"ENCRYPTED PRIVATE KEY");
}

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
							 RandomNumberGenerator& rng,
							 Tuple!(bool, string) delegate() get_pass)
{
	AlgorithmIdentifier alg_id;
	SafeVector!byte pkcs8_key = PKCS8_decode(source, get_pass, alg_id);

	const string alg_name = OIDS::lookup(alg_id.oid);
	if (alg_name == "" || alg_name == alg_id.oid.as_string())
		throw new PKCS8_Exception("Unknown algorithm OID: " +
									 alg_id.oid.as_string());

	return make_Private_Key(alg_id, pkcs8_key, rng);
}

/*
* Extract a private key and return it
*/
Private_Key* load_key(in string fsname,
							 RandomNumberGenerator& rng,
							 Tuple!(bool, string) delegate() get_pass)
{
	DataSource_Stream source(fsname, true);
	return PKCS8::load_key(source, rng, get_pass);
}

namespace {

class Single_Shot_Passphrase
{
	public:
		Single_Shot_Passphrase(in string pass) :
			passphrase(pass), first(true) {}

		Pair!(bool, string) operator()()
		{
			if (first)
			{
				first = false;
				return Pair(true, passphrase);
			}
			else
				return Pair(false, "");
		}

	private:
		string passphrase;
		bool first;
};

}

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
							 RandomNumberGenerator& rng,
							 in string pass)
{
	return PKCS8::load_key(source, rng, Single_Shot_Passphrase(pass));
}

/*
* Extract a private key and return it
*/
Private_Key* load_key(in string fsname,
							 RandomNumberGenerator& rng,
							 in string pass)
{
	return PKCS8::load_key(fsname, rng, Single_Shot_Passphrase(pass));
}

/*
* Make a copy of this private key
*/
Private_Key* copy_key(in Private_Key key,
							 RandomNumberGenerator& rng)
{
	DataSource_Memory source(PEM_encode(key));
	return PKCS8::load_key(source, rng);
}

}

}
