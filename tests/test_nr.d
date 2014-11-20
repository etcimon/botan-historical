#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
  #include <botan/auto_rng.h>
  #include <botan/pubkey.h>
  #include <botan/dl_group.h>
#endif

#include <botan/hex.h>
#include <iostream>
#include <fstream>



#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

size_t nr_sig_kat(string p,
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

	auto privkey = scoped!NR_PrivateKey(rng, group, x_bn);

	auto pubkey = scoped!NR_PublicKey(privkey);

	const string padding = "EMSA1(" ~ hash ~ ")";

	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);

	return validate_signature(verify, sign, "nr/" ~ hash, msg, rng, nonce, signature);
}

#endif

size_t test_nr()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	File nr_sig = File("test_data/pubkey/nr.vec", "r");

	fails += run_tests_bb(nr_sig, "NR Signature", "Signature", true,
							 (string[string] m)
							 {
							 	return nr_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
							 });
#endif

	return fails;
}

