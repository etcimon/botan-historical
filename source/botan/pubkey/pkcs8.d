/*
* PKCS #8
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pkcs8;

import botan.pubkey.x509_key;
import functional;
import std.datetime;
import botan.rng.rng;
import botan.filters.pipe;
import botan.pbe.factory;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oid_lookup.oids;
import botan.codec.pem;
import botan.pubkey.pk_algs;
import botan.utils.types;

/**
* PKCS #8 General Exception
*/
final class PKCS8_Exception : Decoding_Error
{
	this(in string error)
	{
		super("PKCS #8: " ~ error);
	}
};

/**
* BER encode a private key
* @param key the private key to encode
* @return BER encoded key
*/
Secure_Vector!ubyte BER_encode(in Private_Key key)
{
	const size_t PKCS8_VERSION = 0;
	
	return DER_Encoder()
		.start_cons(ASN1_Tag.SEQUENCE)
			.encode(PKCS8_VERSION)
			.encode(key.pkcs8_algorithm_identifier())
			.encode(key.pkcs8_private_key(), ASN1_Tag.OCTET_STRING)
			.end_cons()
			.get_contents();
}

/**
* Get a string containing a PEM encoded private key.
* @param key the key to encode
* @return encoded key
*/
string PEM_encode(in Private_Key key)
{
	return pem.encode(BER_encode(key), "PRIVATE KEY");
}

/**
* Encrypt a key using PKCS #8 encryption
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param dur number of time to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
			algorithm; if empty ("") a reasonable (portable/secure)
			default will be chosen.
* @return encrypted key in binary BER form
*/
Vector!ubyte BER_encode(in Private_Key key,
                        RandomNumberGenerator rng,
                        in string pass,
                        Duration dur = 300.msecs,
                        in string pbe_algo = "")
{
	const string DEFAULT_PBE = "PBE-PKCS5v20(SHA-1,AES-256/CBC)";
	
	Unique!PBE pbe =
		get_pbe(((pbe_algo != "") ? pbe_algo : DEFAULT_PBE),
		        pass,
		        dur,
		        rng);
	
	Algorithm_Identifier pbe_algid = Algorithm_Identifier(pbe.get_oid(), pbe.encode_params());
	
	Pipe key_encrytor = Pipe(*pbe);
	key_encrytor.process_msg(BER_encode(key));
	
	return DER_Encoder()
		.start_cons(ASN1_Tag.SEQUENCE)
			.encode(pbe_algid)
			.encode(key_encrytor.read_all(), ASN1_Tag.OCTET_STRING)
			.end_cons()
			.get_contents_unlocked();
}

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param msec number of milliseconds to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
			algorithm; if empty ("") a reasonable (portable/secure)
			default will be chosen.
* @return encrypted key in PEM form
*/
string PEM_encode(in Private_Key key,
                  RandomNumberGenerator rng,
                  in string pass,
                  Duration dur = 300.msecs,
                  in string pbe_algo = "")
{
	if (pass == "")
		return PEM_encode(key);

	return pem.encode(BER_encode(key, rng, pass, dur, pbe_algo),
	                  "ENCRYPTED PRIVATE KEY");
}

/**
* Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
Private_Key load_key(DataSource source,
                     RandomNumberGenerator rng,
                     Single_Shot_Passphrase get_pass)
{
	Algorithm_Identifier alg_id;
	Secure_Vector!ubyte pkcs8_key = PKCS8_decode(source, get_pass, alg_id);
	
	const string alg_name = oids.lookup(alg_id.oid);
	if (alg_name == "" || alg_name == alg_id.oid.toString())
		throw new PKCS8_Exception("Unknown algorithm OID: " ~
		                          alg_id.oid.toString());
	
	return make_private_key(alg_id, pkcs8_key, rng);
}

/** Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
Private_Key load_key(DataSource source,
                     RandomNumberGenerator rng,
                     in string pass = "")
{
	return load_key(source, rng, Single_Shot_Passphrase(pass));
}

/**
* Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
Private_Key load_key(in string filename,
                     RandomNumberGenerator rng,
                     Single_Shot_Passphrase get_pass)
{
	auto source = scoped!DataSource_Stream(filename, true);
	return load_key(source, rng, get_pass);
}

/** Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
Private_Key load_key(in string filename,
                     RandomNumberGenerator rng,
                     in string pass = "")
{
	return load_key(filename, rng, Single_Shot_Passphrase(pass));
}


/**
* Copy an existing encoded key object.
* @param key the key to copy
* @param rng the rng to use
* @return new copy of the key
*/
Private_Key copy_key(in Private_Key key,
                     RandomNumberGenerator rng)
{
	auto source = scoped!DataSource_Memory(PEM_encode(key));
	return load_key(source, rng);
}

/*
* Get info from an EncryptedPrivateKeyInfo
*/
Secure_Vector!ubyte PKCS8_extract(DataSource source,
                               Algorithm_Identifier pbe_alg_id)
{
	Secure_Vector!ubyte key_data;
	
	BER_Decoder(source)
		.start_cons(ASN1_Tag.SEQUENCE)
			.decode(pbe_alg_id)
			.decode(key_data, ASN1_Tag.OCTET_STRING)
			.verify_end();
	
	return key_data;
}

/*
* PEM decode and/or decrypt a private key
*/
Secure_Vector!ubyte PKCS8_decode(
	DataSource source,
	Single_Shot_Passphrase get_passphrase,
	Algorithm_Identifier pk_alg_id)
{
	Algorithm_Identifier pbe_alg_id;
	Secure_Vector!ubyte key_data, key;
	bool is_encrypted = true;
	
	try {
		if (asn1_obj.maybe_BER(source) && !pem.matches(source))
			key_data = PKCS8_extract(source, pbe_alg_id);
		else
		{
			string label;
			key_data = pem.decode(source, label);
			if (label == "PRIVATE KEY")
				is_encrypted = false;
			else if (label == "ENCRYPTED PRIVATE KEY")
			{
				auto key_source = scoped!DataSource_Memory(key_data);
				key_data = PKCS8_extract(key_source, pbe_alg_id);
			}
			else
				throw new PKCS8_Exception("Unknown PEM label " ~ label);
		}
		
		if (key_data.empty)
			throw new PKCS8_Exception("No key data found");
	}
	catch(Decoding_Error e)
	{
		throw new Decoding_Error("PKCS #8 private key decoding failed: " ~ string(e.what()));
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
				
				Pipe decryptor = Pipe(get_pbe(pbe_alg_id.oid, pbe_alg_id.parameters, pass.second));
				
				decryptor.process_msg(key_data);
				key = decryptor.read_all();
			}
			
			BER_Decoder(key)
				.start_cons(ASN1_Tag.SEQUENCE)
					.decode_and_check!size_t(0, "Unknown PKCS #8 version number")
					.decode(pk_alg_id)
					.decode(key, ASN1_Tag.OCTET_STRING)
					.discard_remaining()
					.end_cons();
			
			break;
		}
		catch(Decoding_Error)
		{
			++tries;
		}
	}
	
	if (key.empty)
		throw new Decoding_Error("PKCS #8 private key decoding failed");
	return key;
}


private struct Single_Shot_Passphrase
{
public:
	this(in string pass) 
	{
		passphrase = pass;
		first = true;
	}
	
	Pair!(bool, string) opCall()
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
