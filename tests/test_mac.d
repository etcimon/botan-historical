#include "tests.h"

#include <botan/libstate.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t mac_test(string algo,
					 string key_hex,
					 string in_hex,
					 string out_hex)
{
	Algorithm_Factory af = global_state().algorithm_factory();

	const auto providers = af.providers_of(algo);
	size_t fails = 0;

	if(providers.empty())
	{
		writeln("Unknown algo ~ " algo);
		++fails;
	}

	for(auto provider: providers)
	{
		auto proto = af.prototype_mac(algo, provider);

		if(!proto)
		{
			writeln("Unable to get " ~ algo ~ " from " ~ provider);
			++fails;
			continue;
		}

		std::unique_ptr<MessageAuthenticationCode> mac(proto.clone());

		mac.set_key(hex_decode(key_hex));
		mac.update(hex_decode(in_hex));

		auto h = mac.final();

		if(h != hex_decode_locked(out_hex))
		{
			writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
			++fails;
		}
	}

	return fails;
}

}

size_t test_mac()
{
	auto test = [](string input)
	{
		File vec(input);

		return run_tests_bb(vec, "Mac", "Out", true,
				 (string[string] m)
				 {
				 return mac_test(m["Mac"], m["Key"], m["In"], m["Out"]);
				 });
	};

	return run_tests_in_dir(TEST_DATA_DIR "mac", test);
}
