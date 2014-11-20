#include "tests.h"

#include <botan/libstate.h>
#include <botan/stream_cipher.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>



namespace {

size_t stream_test(string algo,
						 string key_hex,
						 string in_hex,
						 string out_hex,
						 string nonce_hex)
{
	const Secure_Vector!ubyte key = hex_decode_locked(key_hex);
	const Secure_Vector!ubyte pt = hex_decode_locked(in_hex);
	const Secure_Vector!ubyte ct = hex_decode_locked(out_hex);
	const Secure_Vector!ubyte nonce = hex_decode_locked(nonce_hex);

	Algorithm_Factory af = global_state().algorithm_factory();

	const auto providers = af.providers_of(algo);
	size_t fails = 0;

	if (providers.empty)
	{
		writeln("Unknown algo ~ " algo);
		++fails;
	}

	for(auto provider: providers)
	{
		const StreamCipher* proto = af.prototype_stream_cipher(algo, provider);

		if (!proto)
		{
			writeln("Unable to get " ~ algo ~ " from provider '" ~ provider ~ "'");
			++fails;
			continue;
		}

		Unique!StreamCipher cipher(proto.clone());
		cipher.set_key(key);

		if (nonce.length)
			cipher.set_iv(&nonce[0], nonce.length);

		Secure_Vector!ubyte buf = pt;

		cipher.encrypt(buf);

		if (buf != ct)
		{
			writeln(algo ~ " " ~ provider ~ " enc " ~ hex_encode(buf) ~ " != " ~ out_hex);
			++fails;
		}
	}

	return fails;
}

}

size_t test_stream()
{
	auto test = (string input)
	{
		File vec = File(input, "r");

		return run_tests_bb(vec, "StreamCipher", "Out", true,
				 (string[string] m)
				 {
				 return stream_test(m["StreamCipher"], m["Key"], m["In"], m["Out"], m["Nonce"]);
				 });
	};

	return run_tests_in_dir("test_data/stream", test);
}
