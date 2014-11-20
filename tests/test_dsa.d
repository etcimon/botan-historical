#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

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

	BigInt p_bn = BigInt(p);
	BigInt q_bn = BigInt(q);
	BigInt g_bn = BigInt(g);
	BigInt x_bn = BigInt(x);

	DL_Group group = DL_Group(p_bn, q_bn, g_bn);
	auto privkey = scoped!DSA_PrivateKey(rng, group, x_bn);

	auto pubkey = scoped!DSA_PublicKey(privkey);

	const string padding = "EMSA1(" ~ hash ~ ")";

	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);

	return validate_signature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}


size_t test_dsa()
{
	size_t fails = 0;

	File dsa_sig = File("test_data/pubkey/dsa.vec", "r");

	fails += run_tests_bb(dsa_sig, "DSA Signature", "Signature", true,
							 (string[string] m)
							 {
							 return dsa_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
							 });

	return fails;
}

