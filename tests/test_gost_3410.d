#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_GOST_34_10_2001)
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/gost_3410.h>
#include <botan/oids.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>


size_t gost_verify(string group_id,
					 string x,
					 string hash,
					 string msg,
					 string signature)
{
	AutoSeeded_RNG rng;

	EC_Group group = EC_Group(OIDS.lookup(group_id));
	PointGFp public_point = OS2ECP(hex_decode(x), group.get_curve());

	auto gost = scoped!GOST_3410_PublicKey(group, public_point);

	const string padding = "EMSA1(" ~ hash ~ ")";

	PK_Verifier v = PK_Verifier(gost, padding);

	if (!v.verify_message(hex_decode(msg), hex_decode(signature)))
		return 1;

	return 0;
}

#endif

size_t test_gost_3410()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_GOST_34_10_2001)
	File ecdsa_sig = File("test_data/pubkey/gost_3410.vec", "r");

	fails += run_tests_bb(ecdsa_sig, "GOST-34.10 Signature", "Signature", true,
						 (string[string] m)
						 {
						 return gost_verify(m["Group"], m["Pubkey"], m["Hash"], m["Msg"], m["Signature"]);
						 });
#endif

	return fails;
}

