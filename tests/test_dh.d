#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>



namespace {

size_t dh_sig_kat(string p,
						string g,
						string x,
						string y,
						string kdf,
						string outlen,
						string key)
{
	AutoSeeded_RNG rng;

	BigInt p_bn(p), g_bn(g), x_bn(x), y_bn(y);

	DL_Group domain(p_bn, g_bn);

	DH_PrivateKey mykey(rng, domain, x_bn);
	DH_PublicKey otherkey(domain, y_bn);

	if(kdf == "")
		kdf = "Raw";

	size_t keylen = 0;
	if(outlen != "")
		keylen = to!uint(outlen);

	PK_Key_Agreement kas(mykey, kdf);

	return validate_kas(kas, "DH/" ~ kdf, otherkey.public_value(), key, keylen);
}

}
#endif

size_t test_dh()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	File dh_sig("test_data/pubkey/dh.vec");

	fails += run_tests_bb(dh_sig, "DH Kex", "K", true,
				 (string[string] m)
				 {
				 return dh_sig_kat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
				 });
#endif

	return fails;
}

