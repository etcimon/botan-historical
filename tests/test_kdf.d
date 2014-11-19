#include "tests.h"

#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

size_t test_kdf()
{
	auto test = (string input) {
		return run_tests(input, "KDF", "Output", true,
				 (string[string] vec)
				 {
				 std::unique_ptr<KDF> kdf(get_kdf(vec["KDF"]));

				 const size_t outlen = to!uint(vec["OutputLen"]);
				 const auto salt = hex_decode(vec["Salt"]);
				 const auto secret = hex_decode(vec["Secret"]);

				 const auto key = kdf.derive_key(outlen, secret, salt);

				 return hex_encode(key);
				 });
	};

	return run_tests_in_dir(TEST_DATA_DIR "kdf", test);
}
