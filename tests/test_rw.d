#include "tests.h"
#include "test_pubkey.h"

#include <botan/hex.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_RW)
  #include <botan/auto_rng.h>
  #include <botan/pubkey.h>
  #include <botan/rw.h>
#endif



#if defined(BOTAN_HAS_RW)
const string padding = "EMSA2(SHA-1)";

size_t rw_sig_kat(string e,
				  string p,
				  string q,
				  string msg,
				  string signature)
{
	AutoSeeded_RNG rng;

	auto privkey = scoped!RW_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));

	auto pubkey = scoped!RW_PublicKey(privkey);

	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);

	return validate_signature(verify, sign, "RW/" ~ padding, msg, rng, signature);
}

size_t rw_sig_verify(string e,
							 string n,
							 string msg,
							 string signature)
{
	AutoSeeded_RNG rng;

	BigInt e_bn = BigInt(e);
	BigInt n_bn = BigInt(n);

	auto key = scoped!RW_PublicKey(n_bn, e_bn);

	PK_Verifier verify = PK_Verifier(key, padding);

	if (!verify.verify_message(hex_decode(msg), hex_decode(signature)))
		return 1;
	return 0;
}

#endif

size_t test_rw()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_RW)
	File rw_sig = File("test_data/pubkey/rw_sig.vec", "r");
	File rw_verify = File("test_data/pubkey/rw_verify.vec", "r");

	fails += run_tests_bb(rw_sig, "RW Signature", "Signature", true,
							 (string[string] m)
							 {
							 	return rw_sig_kat(m["E"], m["P"], m["Q"], m["Msg"], m["Signature"]);
							 });

	fails += run_tests_bb(rw_verify, "RW Verify", "Signature", true,
							 (string[string] m)
							 {
							 	return rw_sig_verify(m["E"], m["N"], m["Msg"], m["Signature"]);
							 });
#endif

	return fails;
}

