/*
* PBE Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.get_pbe;
import botan.oids;
import botan.scan_name;
import botan.parsing;
import botan.libstate;

#if defined(BOTAN_HAS_PBE_PKCS_V20)
  import botan.pbes2;
  import botan.hmac;
#endif
/*
* Get an encryption PBE, set new parameters
*/
PBE* get_pbe(in string algo_spec,
				 in string passphrase,
				 std::chrono::milliseconds msec,
				 RandomNumberGenerator& rng)
{
	SCAN_Name request(algo_spec);

	const string pbe = request.algo_name();
	string digest_name = request.arg(0);
	const string cipher = request.arg(1);

	Vector!( string ) cipher_spec = split_on(cipher, '/');
	if (cipher_spec.size() != 2)
		throw new Invalid_Argument("PBE: Invalid cipher spec " + cipher);

	const string cipher_algo = SCAN_Name::deref_alias(cipher_spec[0]);
	const string cipher_mode = cipher_spec[1];

	if (cipher_mode != "CBC")
		throw new Invalid_Argument("PBE: Invalid cipher mode " + cipher);

	Algorithm_Factory& af = global_state().algorithm_factory();

	const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_algo);
	if (!block_cipher)
		throw new Algorithm_Not_Found(cipher_algo);

	const HashFunction* hash_function = af.prototype_hash_function(digest_name);
	if (!hash_function)
		throw new Algorithm_Not_Found(digest_name);

	if (request.arg_count() != 2)
		throw new Invalid_Algorithm_Name(algo_spec);

#if defined(BOTAN_HAS_PBE_PKCS_V20)
	if (pbe == "PBE-PKCS5v20")
		return new PBE_PKCS5v20(block_cipher->clone(),
										new HMAC(hash_function->clone()),
										passphrase,
										msec,
										rng);
#endif

	throw new Algorithm_Not_Found(algo_spec);
}

/*
* Get a decryption PBE, decode parameters
*/
PBE* get_pbe(in OID pbe_oid,
				 in Vector!byte params,
				 in string passphrase)
{
	SCAN_Name request(OIDS::lookup(pbe_oid));

	const string pbe = request.algo_name();

#if defined(BOTAN_HAS_PBE_PKCS_V20)
	if (pbe == "PBE-PKCS5v20")
		return new PBE_PKCS5v20(params, passphrase);
#endif

	throw new Algorithm_Not_Found(pbe_oid.as_string());
}

}
