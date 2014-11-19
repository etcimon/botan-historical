#include "tests.h"
#include <botan/hex.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_HKDF)
#include <botan/libstate.h>
#include <botan/hkdf.h>

using namespace Botan;

namespace {

Secure_Vector!ubyte hkdf(string hkdf_algo,
								 in Secure_Vector!ubyte ikm,
								 in Secure_Vector!ubyte salt,
								 in Secure_Vector!ubyte info,
								 size_t L)
{
	Algorithm_Factory af = global_state().algorithm_factory();

	const string algo = hkdf_algo[5 .. hkdf_algo.length-6+5];

	const MessageAuthenticationCode* mac_proto = af.prototype_mac("HMAC(" + algo + ")");

	if(!mac_proto)
		throw new Invalid_Argument("Bad HKDF hash '" + algo + "'");

	HKDF hkdf(mac_proto.clone(), mac_proto.clone());

	hkdf.start_extract(&salt[0], salt.length);
	hkdf.extract(&ikm[0], ikm.length);
	hkdf.finish_extract();

	Secure_Vector!ubyte key(L);
	hkdf.expand(&key[0], key.length, &info[0], info.length);
	return key;
}

size_t hkdf_test(string algo,
					string ikm,
					string salt,
					string info,
					string okm,
					size_t L)
{
	const string got = hex_encode(
		hkdf(algo,
			  hex_decode_locked(ikm),
			  hex_decode_locked(salt),
			  hex_decode_locked(info),
			  L)
		);

	if(got != okm)
	{
		writeln("HKDF got " ~ got ~ " expected " ~ okm);
		return 1;
	}

	return 0;
}

}
#endif

size_t test_hkdf()
{
#if defined(BOTAN_HAS_HKDF)
	File vec(TEST_DATA_DIR "/hkdf.vec");

	return run_tests_bb(vec, "HKDF", "OKM", true,
				 (string[string] m)
				 {
				 return hkdf_test(m["HKDF"], m["IKM"], m["salt"], m["info"],
										m["OKM"], to!uint(m["L"]));
				 });
#else
	return 0;
#endif
}
