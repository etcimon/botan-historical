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

using namespace Botan;

namespace {

size_t ecdsa_sig_kat(string group_id,
							string x,
							string hash,
							string msg,
							string nonce,
							string signature)
{
	AutoSeeded_RNG rng;

	EC_Group group(OIDS::lookup(group_id));
	ECDSA_PrivateKey ecdsa(rng, group, BigInt(x));

	const string padding = "EMSA1(" + hash + ")";

	PK_Verifier verify(ecdsa, padding);
	PK_Signer sign(ecdsa, padding);

	return validate_signature(verify, sign, "DSA/" + hash, msg, rng, nonce, signature);
}

}
#endif

size_t test_ecdsa()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_ECDSA)
	File ecdsa_sig(PK_TEST_DATA_DIR "/ecdsa.vec");

	fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", true,
				 (string[string] m)
				 {
				 return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
				 });
#endif

	return fails;
}
