#include "tests.h"
#include "test_pubkey.h"

#include <botan/hex.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
  #include <botan/auto_rng.h>
  #include <botan/pubkey.h>
  #include <botan/dl_group.h>
#endif



#if defined(BOTAN_HAS_ELGAMAL)


size_t elgamal_kat(string p,
						 string g,
						 string x,
						 string msg,
						 string padding,
						 string nonce,
						 string ciphertext)
{
	AutoSeeded_RNG rng;

	const BigInt p_bn = BigInt(p);
	const BigInt g_bn = BigInt(g);
	const BigInt x_bn = BigInt(x);

	DL_Group group = DL_Group(p_bn, g_bn);
	auto privkey = scoped!ElGamal_PrivateKey(rng, group, x_bn);

	auto pubkey = scoped!ElGamal_PublicKey(privkey);

	if (padding == "")
		padding = "Raw";

	auto enc = scoped!PK_Encryptor_EME(pubkey, padding);
	auto dec = scoped!PK_Decryptor_EME(privkey, padding);

	return validate_encryption(enc, dec, "ElGamal/" ~ padding, msg, nonce, ciphertext);
}

#endif

size_t test_elgamal()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_ELGAMAL)
	File elgamal_enc = File("test_data/pubkey/elgamal.vec", "r");

	fails += run_tests_bb(elgamal_enc, "ElGamal Encryption", "Ciphertext", true,
							 (string[string] m)
							 {
							 return elgamal_kat(m["P"], m["G"], m["X"], m["Msg"],
													m["Padding"], m["Nonce"], m["Ciphertext"]);
							 });
#endif

	return fails;
}
