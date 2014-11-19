#include "tests.h"
#include "test_pubkey.h"

#include <botan/hex.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_DLIES)
 #include <botan/auto_rng.h>
 #include <botan/pubkey.h>
 #include <botan/lookup.h>
 #include <botan/dlies.h>
 #include <botan/dh.h>
#endif

using namespace Botan;

#if defined(BOTAN_HAS_DLIES)
namespace {

size_t dlies_kat(string p,
					  string g,
					  string x1,
					  string x2,
					  string msg,
					  string ciphertext)
{
	AutoSeeded_RNG rng;

	BigInt p_bn(p);
	BigInt g_bn(g);
	BigInt x1_bn(x1);
	BigInt x2_bn(x2);

	DL_Group domain(p_bn, g_bn);

	DH_PrivateKey from(rng, domain, x1_bn);
	DH_PrivateKey to(rng, domain, x2_bn);

	const string opt_str = "KDF2(SHA-1)/HMAC(SHA-1)/16";

	Vector!string options = split_on(opt_str, '/');

	if(options.length != 3)
		throw new Exception("DLIES needs three options: " + opt_str);

	const size_t mac_key_len = to!uint(options[2]);

	DLIES_Encryptor e(from,
							get_kdf(options[0]),
							get_mac(options[1]),
							mac_key_len);

	DLIES_Decryptor d(to,
							get_kdf(options[0]),
							get_mac(options[1]),
							mac_key_len);

	e.set_other_key(to.public_value());

	const string empty = "";
	return validate_encryption(e, d, "DLIES", msg, empty, ciphertext);
}

}
#endif

size_t test_dlies()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_DLIES)
	File dlies(PK_TEST_DATA_DIR "/dlies.vec");

	fails += run_tests_bb(dlies, "DLIES Encryption", "Ciphertext", true,
				 (string[string] m)
				 {
				 return dlies_kat(m["P"], m["G"], m["X1"], m["X2"], m["Msg"], m["Ciphertext"]);
				 });
#endif

	return fails;
}

