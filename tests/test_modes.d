#include "tests.h"

#include <botan/hex.h>
#include <botan/lookup.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>
#include <iostream>
#include <fstream>
#include <memory>



namespace {

Secure_Vector!ubyte run_mode(string algo, Cipher_Dir dir, in Secure_Vector!ubyte pt, in Secure_Vector!ubyte nonce, in Secure_Vector!ubyte key)
{
#if 0
	Unique!Cipher_Mode cipher(get_cipher(algo, dir));

	cipher.set_key(key);
	cipher.start_vec(nonce);

	Secure_Vector!ubyte ct = pt;
	cipher.finish(ct);
#endif

	Pipe pipe(get_cipher(algo, SymmetricKey(key), InitializationVector(nonce), dir));

	pipe.process_msg(pt);

	return pipe.read_all();
}

size_t mode_test(string algo, string pt, string ct, string key_hex, string nonce_hex)
{
	auto nonce = hex_decode_locked(nonce_hex);
	auto key = hex_decode_locked(key_hex);

	size_t fails = 0;

	const string ct2 = hex_encode(run_mode(algo, ENCRYPTION, hex_decode_locked(pt), nonce, key));

	if(ct != ct2)
	{
		writeln(algo ~ " got ct " ~ ct2 ~ " expected " ~ ct);
		++fails;
	}

	const string pt2 = hex_encode(run_mode(algo, DECRYPTION, hex_decode_locked(ct), nonce, key));

	if(pt != pt2)
	{
		writeln(algo ~ " got pt " ~ pt2 ~ " expected " ~ pt);
		++fails;
	}

	return fails;
}

}

size_t test_modes()
{
	auto test = (string input)
	{
		File vec(input);

		return run_tests_bb(vec, "Mode", "Out", true,
				 (string[string] m)
				 {
				 return mode_test(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
				 });
	};

	return run_tests_in_dir("test_data/modes", test);
}
