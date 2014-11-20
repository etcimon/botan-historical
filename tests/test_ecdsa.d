#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_ECDSA)
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/oids.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>


size_t ecdsa_sig_kat(string group_id,
							string x,
							string hash,
							string msg,
							string nonce,
							string signature)
{
	AutoSeeded_RNG rng;

	EC_Group group = EC_Group(OIDS.lookup(group_id));
	auto ecdsa = scoped!ECDSA_PrivateKey(rng, group, BigInt(x));

	const string padding = "EMSA1(" ~ hash ~ ")";

	PK_Verifier verify = PK_Verifier(ecdsa, padding);
	PK_Signer sign = PK_Signer(ecdsa, padding);

	return validate_signature(verify, sign, "DSA/" ~ hash, msg, rng, nonce, signature);
}

#endif

size_t test_ecdsa()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_ECDSA)
	File ecdsa_sig = File("test_data/pubkey/ecdsa.vec", "r");

	fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", true,
						 (string[string] m)
						 {
						 return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
						 });
#endif

	return fails;
}
