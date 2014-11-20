#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>


size_t dh_sig_kat(string p,
						string g,
						string x,
						string y,
						string kdf,
						string outlen,
						string key)
{
	AutoSeeded_RNG rng;

	BigInt p_bn = BigInt(p);
	BigInt g_bn = BigInt(g);
	BigInt x_bn = BigInt(x);
	BigInt y_bn = BigInt(y);

	DL_Group domain = DL_Group(p_bn, g_bn);

	auto mykey = scoped!DH_PrivateKey(rng, domain, x_bn);
	auto otherkey = scoped!DH_PublicKey(domain, y_bn);

	if (kdf == "")
		kdf = "Raw";

	size_t keylen = 0;
	if (outlen != "")
		keylen = to!uint(outlen);

	auto kas = scoped!PK_Key_Agreement(mykey, kdf);

	return validate_kas(kas, "DH/" ~ kdf, otherkey.public_value(), key, keylen);
}
#endif

size_t test_dh()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	File dh_sig = File("test_data/pubkey/dh.vec", "r");

	fails += run_tests_bb(dh_sig, "DH Kex", "K", true,
				 (string[string] m)
				 {
				 return dh_sig_kat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
				 });
#endif

	return fails;
}

