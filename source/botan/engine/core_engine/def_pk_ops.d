/*
* PK Operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;

#if defined(BOTAN_HAS_RSA)
  import botan.rsa;
#endif

#if defined(BOTAN_HAS_RW)
  import botan.rw;
#endif

#if defined(BOTAN_HAS_DSA)
  import botan.dsa;
#endif

#if defined(BOTAN_HAS_ECDSA)
  import botan.ecdsa;
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  import botan.elgamal;
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  import botan.gost_3410;
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  import botan.nr;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  import botan.dh;
#endif

#if defined(BOTAN_HAS_ECDH)
  import botan.ecdh;
#endif
PK_Ops::Encryption*
Core_Engine::get_encryption_op(in Public_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
	if (in ElGamal_PublicKey* s = cast(const ElGamal_PublicKey*)(key))
		return new ElGamal_Encryption_Operation(*s);
#endif

	return null;
}

PK_Ops::Decryption*
Core_Engine::get_decryption_op(in Private_Key key, RandomNumberGenerator& rng) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new RSA_Private_Operation(*s, rng);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
	if (in ElGamal_PrivateKey* s = cast(const ElGamal_PrivateKey*)(key))
		return new ElGamal_Decryption_Operation(*s, rng);
#endif

	return null;
}

PK_Ops::Key_Agreement*
Core_Engine::get_key_agreement_op(in Private_Key key, RandomNumberGenerator& rng) const
{
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	if (in DH_PrivateKey* dh = cast(const DH_PrivateKey*)(key))
		return new DH_KA_Operation(*dh, rng);
#endif

#if defined(BOTAN_HAS_ECDH)
	if (in ECDH_PrivateKey* ecdh = cast(const ECDH_PrivateKey*)(key))
		return new ECDH_KA_Operation(*ecdh);
#endif

	return null;
}

PK_Ops::Signature*
Core_Engine::get_signature_op(in Private_Key key, RandomNumberGenerator& rng) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new RSA_Private_Operation(*s, rng);
#endif

#if defined(BOTAN_HAS_RW)
	if (in RW_PrivateKey* s = cast(const RW_PrivateKey*)(key))
		return new RW_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PrivateKey* s = cast(const DSA_PrivateKey*)(key))
		return new DSA_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_ECDSA)
	if (in ECDSA_PrivateKey* s = cast(const ECDSA_PrivateKey*)(key))
		return new ECDSA_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
	if (const GOST_3410_PrivateKey* s =
			cast(in GOST_3410_PrivateKey*)(key))
		return new GOST_3410_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	if (in NR_PrivateKey* s = cast(const NR_PrivateKey*)(key))
		return new NR_Signature_Operation(*s);
#endif

	return null;
}

PK_Ops::Verification*
Core_Engine::get_verify_op(in Public_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_RW)
	if (in RW_PublicKey* s = cast(const RW_PublicKey*)(key))
		return new RW_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PublicKey* s = cast(const DSA_PublicKey*)(key))
		return new DSA_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_ECDSA)
	if (in ECDSA_PublicKey* s = cast(const ECDSA_PublicKey*)(key))
		return new ECDSA_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
	if (const GOST_3410_PublicKey* s =
			cast(in GOST_3410_PublicKey*)(key))
		return new GOST_3410_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	if (in NR_PublicKey* s = cast(const NR_PublicKey*)(key))
		return new NR_Verification_Operation(*s);
#endif

	return null;
}

}
