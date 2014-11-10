/*
* PK Key Factory
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pk_algs;

import botan.pubkey.pk_keys;
import botan.asn1.oid_lookup.oids;

static if (BOTAN_HAS_RSA)  				import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)  				import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_DIFFIE_HELLMAN)  	import botan.pubkey.algo.dh;
static if (BOTAN_HAS_ECDSA)  			import botan.pubkey.algo.ecdsa;
static if (BOTAN_HAS_GOST_34_10_2001) 	import botan.pubkey.algo.gost_3410;
static if (BOTAN_HAS_NYBERG_RUEPPEL)  	import botan.pubkey.algo.nr;
static if (BOTAN_HAS_RW)  				import botan.pubkey.algo.rw;
static if (BOTAN_HAS_ELGAMAL)  			import botan.pubkey.algo.elgamal;
static if (BOTAN_HAS_ECDH) 				import botan.pubkey.algo.ecdh;

Public_Key make_public_key(in Algorithm_Identifier alg_id,
                           in Secure_Vector!ubyte key_bits)
{
	const string alg_name = oids.lookup(alg_id.oid);
	if (alg_name == "")
		throw new Decoding_Error("Unknown algorithm OID: " ~ alg_id.oid.toString());
	
	static if (BOTAN_HAS_RSA) {
		if (alg_name == "RSA")
			return new RSA_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_RW) {
		if (alg_name == "RW")
			return new RW_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_DSA) {
		if (alg_name == "DSA")
			return new DSA_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_DIFFIE_HELLMAN) {
		if (alg_name == "DH")
			return new DH_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_NYBERG_RUEPPEL) {
		if (alg_name == "NR")
			return new NR_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_ELGAMAL) {
		if (alg_name == "ElGamal")
			return new ElGamal_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_ECDSA) {
		if (alg_name == "ECDSA")
			return new ECDSA_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_GOST_34_10_2001) {
		if (alg_name == "GOST-34.10")
			return new GOST_3410_PublicKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_ECDH) {
		if (alg_name == "ECDH")
			return new ECDH_PublicKey(alg_id, key_bits);
	}
	
	return null;
}

Private_Key make_private_key(in Algorithm_Identifier alg_id,
                             in Secure_Vector!ubyte key_bits,
                             RandomNumberGenerator rng)
{
	const string alg_name = oids.lookup(alg_id.oid);
	if (alg_name == "")
		throw new Decoding_Error("Unknown algorithm OID: " ~ alg_id.oid.toString());
	
	static if (BOTAN_HAS_RSA) {
		if (alg_name == "RSA")
			return new RSA_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_RW) {
		if (alg_name == "RW")
			return new RW_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_DSA) {
		if (alg_name == "DSA")
			return new DSA_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_DIFFIE_HELLMAN) {
		if (alg_name == "DH")
			return new DH_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_NYBERG_RUEPPEL) {
		if (alg_name == "NR")
			return new NR_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_ELGAMAL) {
		if (alg_name == "ElGamal")
			return new ElGamal_PrivateKey(alg_id, key_bits, rng);
	}
	
	static if (BOTAN_HAS_ECDSA) {
		if (alg_name == "ECDSA")
			return new ECDSA_PrivateKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_GOST_34_10_2001) {
		if (alg_name == "GOST-34.10")
			return new GOST_3410_PrivateKey(alg_id, key_bits);
	}
	
	static if (BOTAN_HAS_ECDH) {
		if (alg_name == "ECDH")
			return new ECDH_PrivateKey(alg_id, key_bits);
	}
	
	return null;
}