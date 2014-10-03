/*
* PK Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.pk_algs;
import botan.asn1.oid_lookup.oids;

#if defined(BOTAN_HAS_RSA)
  import botan.rsa;
#endif

#if defined(BOTAN_HAS_DSA)
  import botan.dsa;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  import botan.dh;
#endif

#if defined(BOTAN_HAS_ECDSA)
  import botan.ecdsa;
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  import botan.gost_3410;
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  import botan.nr;
#endif

#if defined(BOTAN_HAS_RW)
  import botan.rw;
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  import botan.elgamal;
#endif

#if defined(BOTAN_HAS_ECDH)
  import botan.ecdh;
#endif
Public_Key* make_public_key(in AlgorithmIdentifier alg_id,
									 in SafeVector!byte key_bits)
{
	const string alg_name = oids.lookup(alg_id.oid);
	if (alg_name == "")
		throw new Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
	if (alg_name == "RSA")
		return new RSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_RW)
	if (alg_name == "RW")
		return new RW_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DSA)
	if (alg_name == "DSA")
		return new DSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	if (alg_name == "DH")
		return new DH_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	if (alg_name == "NR")
		return new NR_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
	if (alg_name == "ElGamal")
		return new ElGamal_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDSA)
	if (alg_name == "ECDSA")
		return new ECDSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
	if (alg_name == "GOST-34.10")
		return new GOST_3410_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
	if (alg_name == "ECDH")
		return new ECDH_PublicKey(alg_id, key_bits);
#endif

	return null;
}

Private_Key* make_Private_Key(in AlgorithmIdentifier alg_id,
										in SafeVector!byte key_bits,
										RandomNumberGenerator rng)
{
	const string alg_name = oids.lookup(alg_id.oid);
	if (alg_name == "")
		throw new Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
	if (alg_name == "RSA")
		return new RSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_RW)
	if (alg_name == "RW")
		return new RW_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DSA)
	if (alg_name == "DSA")
		return new DSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	if (alg_name == "DH")
		return new DH_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	if (alg_name == "NR")
		return new NR_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
	if (alg_name == "ElGamal")
		return new ElGamal_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ECDSA)
	if (alg_name == "ECDSA")
		return new ECDSA_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
	if (alg_name == "GOST-34.10")
		return new GOST_3410_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
	if (alg_name == "ECDH")
		return new ECDH_PrivateKey(alg_id, key_bits);
#endif

	return null;
}

}
