#include "tests.h"

#include <botan/libstate.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t hash_test(string algo,
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
		auto proto = af.prototype_hash_function(algo, provider);

		if(!proto)
		{
			writeln("Unable to get " ~ algo ~ " from " ~ provider);
			++fails;
			continue;
		}

		std::unique_ptr<HashFunction> hash(proto.clone());

		hash.update(hex_decode(in_hex));

		auto h = hash.final();

		if(h != hex_decode_locked(out_hex))
		{
			writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
			++fails;
		}

		// Test to make sure clear() resets what we need it to
		hash.update("some discarded input");
		hash.clear();

		hash.update(hex_decode(in_hex));

		h = hash.final();

		if(h != hex_decode_locked(out_hex))
		{
			writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
			++fails;
		}
	}

	return fails;
}

}

size_t test_hash()
{
	auto test = [](string input)
	{
		File vec(input);

		return run_tests_bb(vec, "Hash", "Out", true,
				 (string[string] m)
				 {
				 return hash_test(m["Hash"], m["In"], m["Out"]);
				 });
	};

	return run_tests_in_dir(TEST_DATA_DIR "hash", test);
}
