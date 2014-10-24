/*
* PBE Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbe.factory;

import botan.pbe.pbe;
import botan.utils.types;
import string;
import std.datetime;
import botan.asn1.oid_lookup.oids;
import botan.algo_base.scan_name;
import botan.rng.rng;
import botan.utils.parsing;
import botan.libstate.libstate;
import std.datetime;

static if (BOTAN_HAS_PBE_PKCS_V20) {
	import botan.pbe.pbes2;
	import botan.mac.hmac;
}

/**
* Factory function for PBEs.
* @param algo_spec the name of the PBE algorithm to retrieve
* @param passphrase the passphrase to use for encryption
* @param msec how many milliseconds to run the PBKDF
* @param rng a random number generator
* @return pointer to a PBE with randomly created parameters
*/
PBE get_pbe(in string algo_spec,
             in string passphrase,
             Duration msec,
             RandomNumberGenerator rng)
{
	SCAN_Name request(algo_spec);
	
	const string pbe = request.algo_name;
	string digest_name = request.arg(0);
	const string cipher = request.arg(1);
	
	Vector!string cipher_spec = splitter(cipher, '/');
	if (cipher_spec.length != 2)
		throw new Invalid_Argument("PBE: Invalid cipher spec " ~ cipher);
	
	const string cipher_algo = SCAN_Name::deref_alias(cipher_spec[0]);
	const string cipher_mode = cipher_spec[1];
	
	if (cipher_mode != "CBC")
		throw new Invalid_Argument("PBE: Invalid cipher mode " ~ cipher);
	
	Algorithm_Factory af = global_state().algorithm_factory();
	
	const BlockCipher block_cipher = af.prototype_block_cipher(cipher_algo);
	if (!block_cipher)
		throw new Algorithm_Not_Found(cipher_algo);
	
	const HashFunction hash_function = af.prototype_hash_function(digest_name);
	if (!hash_function)
		throw new Algorithm_Not_Found(digest_name);
	
	if (request.arg_count() != 2)
		throw new Invalid_Algorithm_Name(algo_spec);
	
	static if (BOTAN_HAS_PBE_PKCS_V20) {
		if (pbe == "PBE-PKCS5v20")
			return new PBE_PKCS5v20(block_cipher.clone(),
			                        new HMAC(hash_function.clone()),
			                        passphrase,
			                        msec,
			                        rng);
	}
	
	throw new Algorithm_Not_Found(algo_spec);
}


/**
* Factory function for PBEs.
* @param pbe_oid the oid of the desired PBE
* @param params a DataSource providing the DER encoded parameters to use
* @param passphrase the passphrase to use for decryption
* @return pointer to the PBE with the specified parameters
*/
PBE get_pbe(in OID pbe_oid,
		             in Vector!ubyte params,
		             in string passphrase)
{
	SCAN_Name request = SCAN_Name(oids.lookup(pbe_oid));
	
	const string pbe = request.algo_name;
	
	static if (BOTAN_HAS_PBE_PKCS_V20) {
		if (pbe == "PBE-PKCS5v20")
			return new PBE_PKCS5v20(params, passphrase);
	}
	
	throw new Algorithm_Not_Found(pbe_oid.as_string());
}