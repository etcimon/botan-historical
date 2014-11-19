#include "tests.h"

#include <botan/transform.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

Transformation* get_transform(string algo)
{
	throw new Exception("Unknown transform " + algo);
}

Secure_Vector!ubyte transform_test(string algo,
											  in Secure_Vector!ubyte nonce,
											  in Secure_Vector!ubyte /*key*/,
											  in Secure_Vector!ubyte input)
{
	std::unique_ptr<Transformation> transform(get_transform(algo));

	//transform.set_key(key);
	transform.start_vec(nonce);

	Secure_Vector!ubyte output = input;
	transform.update(output, 0);

	return output;
}

}

size_t test_transform()
{
	File vec(TEST_DATA_DIR "/transform.vec");

	return run_tests(vec, "Transform", "Output", true,
				 (string[string] m)
				 {
				 return hex_encode(transform_test(m["Transform"],
															 hex_decode_locked(m["Nonce"]),
															 hex_decode_locked(m["Key"]),
															 hex_decode_locked(m["Input"])));
				 });
}
