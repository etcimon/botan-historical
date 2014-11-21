/*
* Cipher Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cipher_mode;

import botan.algo_base.transform;

/**
* Interface for cipher modes
*/
class Cipher_Mode : Keyed_Transform
{
public:
	/**
	* Returns true iff this mode provides authentication as well as
	* confidentiality.
	*/
	abstract bool authenticated() const { return false; }
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.lookup;
import botan.filters.filters;

private __gshared size_t total_tests;
Secure_Vector!ubyte run_mode(string algo, Cipher_Dir dir, in Secure_Vector!ubyte pt, in Secure_Vector!ubyte nonce, in Secure_Vector!ubyte key)
{
	/*
	Unique!Cipher_Mode cipher = get_cipher(algo, dir);

	cipher.set_key(key);
	cipher.start_vec(nonce);

	Secure_Vector!ubyte ct = pt;
	cipher.finish(ct);
	*/
	
	Pipe pipe = Pipe(get_cipher(algo, SymmetricKey(key), InitializationVector(nonce), dir));
	
	pipe.process_msg(pt);
	
	return pipe.read_all();
}

size_t mode_test(string algo, string pt, string ct, string key_hex, string nonce_hex)
{
	auto nonce = hex_decode_locked(nonce_hex);
	auto key = hex_decode_locked(key_hex);
	
	size_t fails = 0;
	
	const string ct2 = hex_encode(run_mode(algo, ENCRYPTION, hex_decode_locked(pt), nonce, key));
	atomicOp!"+="(total_tests, 1);
	if (ct != ct2)
	{
		writeln(algo ~ " got ct " ~ ct2 ~ " expected " ~ ct);
		++fails;
	}
	
	const string pt2 = hex_encode(run_mode(algo, DECRYPTION, hex_decode_locked(ct), nonce, key));
	atomicOp!"+="(total_tests, 1);
	if (pt != pt2)
	{
		writeln(algo ~ " got pt " ~ pt2 ~ " expected " ~ pt);
		++fails;
	}
	
	return fails;
}

unittest {
	auto test = (string input)
	{
		File vec = File(input, "r");
		
		return run_tests_bb(vec, "Mode", "Out", true,
		                    (string[string] m) {
								return mode_test(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
							});
	};
	
	size_t fails = run_tests_in_dir("test_data/modes", test);

	test_report("cipher_mode", total_tests, fails);
}
