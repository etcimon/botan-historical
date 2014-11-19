#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_DSA)

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t dsa_sig_kat(string p,
						 string q,
						 string g,
						 string x,
						 string hash,
						 string msg,
						 string nonce,
						 string signature)
{
	AutoSeeded_RNG rng;

	BigInt p_bn(p), q_bn(q), g_bn(g), x_bn(x);

	DL_Group group(p_bn, q_bn, g_bn);
	DSA_PrivateKey privkey(rng, group, x_bn);

	DSA_PublicKey pubkey = privkey;

	const string padding = "EMSA1(" + hash + ")";

	PK_Verifier verify(pubkey, padding);
	PK_Signer sign(privkey, padding);

	return validate_signature(verify, sign, "DSA/" + hash, msg, rng, nonce, signature);
}

}
#endif

size_t test_dsa()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_DSA)
	File dsa_sig(PK_TEST_DATA_DIR "/dsa.vec");

	fails += run_tests_bb(dsa_sig, "DSA Signature", "Signature", true,
				 (string[string] m)
				 {
				 return dsa_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
				 });
#endif

	return fails;
}

