module botan.block.test;

import botan.constants;

// static if (BOTAN_TEST):

import botan.test;
import botan.algo_factory.algo_factory;
import botan.block.block_cipher;
import botan.codec.hex;

size_t block_test(string algo, string key_hex, string in_hex, string out_hex)
{
	const Secure_Vector!ubyte key = hex_decode_locked(key_hex);
	const Secure_Vector!ubyte pt = hex_decode_locked(in_hex);
	const Secure_Vector!ubyte ct = hex_decode_locked(out_hex);
	
	Algorithm_Factory af = global_state().algorithm_factory();
	
	const auto providers = af.providers_of(algo);
	size_t fails = 0;
	
	if(providers.empty())
		throw new Exception("Unknown block cipher " + algo);
	
	foreach (provider; providers)
	{
		const BlockCipher proto = af.prototype_block_cipher(algo, provider);
		
		if(!proto)
		{
			writeln("Unable to get " ~ algo ~ " from " ~ provider);
			++fails;
			continue;
		}
		
		Unique!BlockCipher cipher = proto.clone();
		cipher.set_key(key);
		Secure_Vector!ubyte buf = pt;
		
		cipher.encrypt(buf);
		
		if(buf != ct)
		{
			writeln(algo ~ " " ~ provider ~ " enc " ~ hex_encode(buf) ~ " != " ~ out_hex);
			++fails;
			buf = ct;
		}
		
		cipher.decrypt(buf);
		
		if(buf != pt)
		{
			writeln(algo ~ " " ~ provider ~ " dec " ~ hex_encode(buf) ~ " != " ~ out_hex);
			++fails;
		}
	}
	
	return fails;
}

size_t test_block()
{
	auto test_bc = (string input)
	{
		File vec = File(input, "r");
		
		return run_tests_bb(vec, "BlockCipher", "Out", true,
		                    (string[string] m)
		                    {
								return block_test(m["BlockCipher"], m["Key"], m["In"], m["Out"]);
							});
	};
	
	return run_tests_in_dir("test_data/block", test_bc);
}