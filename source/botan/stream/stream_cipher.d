/*
* Stream Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.stream_cipher;

public import botan.algo_base.sym_algo;
/**
* Base class for all stream ciphers
*/
class StreamCipher : SymmetricAlgorithm
{
public:
	/**
	* Encrypt or decrypt a message
	* @param input the plaintext
	* @param output the ubyte array to hold the output, i.e. the ciphertext
	* @param len the length of both in and out in bytes
	*/
	abstract void cipher(in ubyte* input, ubyte* output, size_t len);

	/**
	* Encrypt or decrypt a message
	* @param buf the plaintext / ciphertext
	* @param len the length of buf in bytes
	*/
	final void cipher1(ubyte* buf, size_t len)
	{ cipher(buf, buf, len); }

	/**
	* Encrypt or decrypt a message
	* @param buf the plaintext / ciphertext
	*/
	final void cipher1(ref ubyte[] buf)
	{ cipher(buf.ptr, buf.ptr, buf.length); }

	final void encipher(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

	final void encrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

	final void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

	/**
	* Resync the cipher using the IV
	* @param iv the initialization vector
	* @param iv_len the length of the IV in bytes
	*/
	abstract void set_iv(const ubyte*, size_t iv_len)
	{
		if (iv_len)
			throw new Invalid_Argument("The stream cipher " ~ name ~
			                           " does not support resyncronization");
	}

	/**
	* @param iv_len the length of the IV in bytes
	* @return if the length is valid for this algorithm
	*/
	abstract bool valid_iv_length(size_t iv_len) const
	{
		return (iv_len == 0);
	}

	/**
	* Get a new object representing the same algorithm as this
	*/
	abstract StreamCipher clone() const;
}

static if (BOTAN_TEST):
import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import core.atomic;

private __gshared size_t total_tests;

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
		writeln("Unknown algo " ~ algo);
		++fails;
	}
	
	foreach (provider; providers)
	{
		atomicOp!"+="(total_tests, 1);
		const StreamCipher* proto = af.prototype_stream_cipher(algo, provider);
		
		if (!proto)
		{
			writeln("Unable to get " ~ algo ~ " from provider '" ~ provider ~ "'");
			++fails;
			continue;
		}
		
		Unique!StreamCipher cipher = proto.clone();
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

unittest
{
	auto test = (string input)
	{
		File vec = File(input, "r");
		
		return run_tests_bb(vec, "StreamCipher", "Out", true,
		                    (string[string] m) {
								return stream_test(m["StreamCipher"], m["Key"], m["In"], m["Out"], m["Nonce"]);
							});
	};
	
	size_t fails = run_tests_in_dir("test_data/stream", test);
	
	test_report("stream", total_tests, fails);
}
