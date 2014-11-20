/*
* Base class for message authentiction codes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.mac;
import botan.algo_base.buf_comp;
import botan.algo_base.sym_algo;
// import string;

import botan.utils.mem_ops;

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class MessageAuthenticationCode : Buffered_Computation, SymmetricAlgorithm
{
public:
	/**
	* Verify a MAC.
	* @param input the MAC to verify as a ubyte array
	* @param length the length of param in
	* @return true if the MAC is valid, false otherwise
	*/
	final bool verify_mac(in ubyte* mac, size_t length)
	{
		Secure_Vector!ubyte our_mac = flush();
		
		if (our_mac.length != length)
			return false;
		
		return same_mem(our_mac.ptr, mac.ptr, length);
	}

	/**
	* Get a new object representing the same algorithm as this
	*/
	abstract MessageAuthenticationCode clone() const;

	/**
	* Get the name of this algorithm.
	* @return name of this algorithm
	*/
	abstract @property string name() const;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;

size_t mac_test(string algo, string key_hex, string in_hex, string out_hex)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	
	const auto providers = af.providers_of(algo);
	size_t fails = 0;
	
	if(providers.empty)
	{
		writeln("Unknown algo " ~ algo);
		++fails;
	}
	
	foreach (provider; providers)
	{
		auto proto = af.prototype_mac(algo, provider);
		
		if(!proto)
		{
			writeln("Unable to get " ~ algo ~ " from " ~ provider);
			++fails;
			continue;
		}
		
		Unique!MessageAuthenticationCode mac = proto.clone();
		
		mac.set_key(hex_decode(key_hex));
		mac.update(hex_decode(in_hex));
		
		auto h = mac.flush();
		
		if(h != hex_decode_locked(out_hex))
		{
			writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
			++fails;
		}
	}
	
	return fails;
}

unittest {	
	auto test = (string input) {
		File vec = File(input, "r");
		
		return run_tests_bb(vec, "Mac", "Out", true,
		                    (string[string] m) {
								return mac_test(m["Mac"], m["Key"], m["In"], m["Out"]);
							});
	};
	
	return run_tests_in_dir("test_data/mac", test);
}
