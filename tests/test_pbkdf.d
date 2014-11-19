#include "tests.h"

#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

size_t test_pbkdf()
{
	auto test = [](string input)
	{
		return run_tests(input, "PBKDF", "Output", true,
				 [](string[string] vec)
				 {
				 std::unique_ptr<PBKDF> pbkdf(get_pbkdf(vec["PBKDF"]));

				 const size_t iterations = to!uint(vec["Iterations"]);
				 const size_t outlen = to!uint(vec["OutputLen"]);
				 const auto salt = hex_decode(vec["Salt"]);
				 const string pass = vec["Passphrase"];

				 const auto key = pbkdf.derive_key(outlen, pass,
																&salt[0], salt.length,
																iterations).bits_of();
				 return hex_encode(key);
				 });
	};

	return run_tests_in_dir(TEST_DATA_DIR "pbkdf", test);
}
