/*
* Runtime benchmarking
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.benchmark.benchmark;
import botan.algo_factory.algo_factory;
import botan.algo_base.buf_comp;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.modes.aead.aead;
import botan.hash.hash;
import botan.mac.mac;
import std.datetime;
import std.conv;
import botan.utils.types;
import std.datetime;
import botan.rng.rng;
import map;
import string;
import std.datetime;

/**
* Time aspects of an algorithm/provider
* @param name the name of the algorithm to test
* @param af the algorithm factory used to create objects
* @param provider the provider to use
* @param rng the rng to use to generate random inputs
* @param runtime total time for the benchmark to run
* @param buf_size size of buffer to benchmark against, in KiB
* @return results a map from op type to operations per second
*/
HashMap!(string, double)
	time_algorithm_ops(in string name,
	                   Algorithm_Factory af,
	                   in string provider,
	                   RandomNumberGenerator rng,
	                   Duration runtime,
	                   size_t buf_size)
{
	const size_t Mebibyte = 1024*1024;
	
	Secure_Vector!ubyte buffer = Secure_Vector!ubyte(buf_size * 1024);
	rng.randomize(&buffer[0], buffer.length);
	
	const double mb_mult = buffer.length / cast(double)(Mebibyte);
	

	{

		const BlockCipher proto = af.prototype_block_cipher(name, provider);
		if (proto) {
			Unique!BlockCipher bc = proto.clone();
			
			const SymmetricKey key = SymmetricKey(rng, bc.maximum_keylength());
			
			HashMap!(string, double) ret;
			ret["key schedule"] = time_op(runtime / 8, { bc.set_key(key); });
			ret["encrypt"] = mb_mult * time_op(runtime / 2, { bc.encrypt(buffer); });
			ret["decrypt"] = mb_mult * time_op(runtime / 2, { bc.decrypt(buffer); });
			return ret;
		}
	}
	{
		const StreamCipher proto = af.prototype_stream_cipher(name, provider);
		if (proto) {
			Unique!StreamCipher sc = proto.clone();
			
			const SymmetricKey key = SymmetricKey(rng, sc.maximum_keylength());
			HashMap!(string, double) ret;
			ret["key schedule"] = time_op(runtime / 8, [&]() { sc.set_key(key); });
			ret[""] = mb_mult * time_op(runtime, [&]() { sc.encipher(buffer); });
			return ret;
		}
	}
	{
		const HashFunction proto = af.prototype_hash_function(name, provider);
		if (proto) {
			Unique!HashFunction h = proto.clone();
			HashMap!(string, double) ret;
			ret[""] = mb_mult * time_op(runtime, { h.update(buffer); });
			return ret;
		}
	}
	{
		const MessageAuthenticationCode proto = af.prototype_mac(name, provider);
		
		if (proto) {
			Unique!MessageAuthenticationCode mac = proto.clone();
			
			const SymmetricKey key = SymmetricKey(rng, mac.maximum_keylength());
			HashMap!(string, double) ret;
			ret["key schedule"] =time_op(runtime / 8, { mac.set_key(key); });
			ret[""] = mb_mult * time_op(runtime, { mac.update(buffer); });
			return ret;
		}
	}
	{
		Unique!AEAD_Mode enc = get_aead(name, ENCRYPTION);
		Unique!AEAD_Mode dec = get_aead(name, DECRYPTION);
		
		if (!enc.isEmpty && !dec.isEmpty)
		{
			const SymmetricKey key = SymmetricKey(rng, enc.key_spec().maximum_keylength());
			HashMap!(string, double) ret;
			ret["key schedule"] = time_op(runtime / 4, { enc.set_key(key); dec.set_key(key); }) / 2;
			ret["encrypt"] = mb_mult * time_op(runtime / 2, { enc.update(buffer, 0); buffer.resize(buf_size*1024); });
			ret["decrypt"] = mb_mult * time_op(runtime / 2, { dec.update(buffer, 0); buffer.resize(buf_size*1024); });
			return ret;
		}
	}
	
			
	return HashMap!(string, double)();
}

/**
* Algorithm benchmark
* @param name the name of the algorithm to test (cipher, hash, or MAC)
* @param af the algorithm factory used to create objects
* @param rng the rng to use to generate random inputs
* @param milliseconds total time for the benchmark to run
* @param buf_size size of buffer to benchmark against, in KiB
* @return results a map from provider to speed in mebibytes per second
*/
HashMap!(string, double)
	algorithm_benchmark(in string name,
	                    Algorithm_Factory af,
	                    RandomNumberGenerator rng,
	                    Duration milliseconds,
	                    size_t buf_size)
{
	const Vector!string providers = af.providers_of(name);
	
	HashMap!(string, double) all_results; // provider . ops/sec
	
	if (!providers.empty)
	{
		const Duration ns_per_provider = milliseconds / providers.length;
		
		foreach (provider; providers)
		{
			auto results = time_algorithm_ops(name, af, provider, rng, ns_per_provider, buf_size);
			all_results[provider] = find_first_in(results, { "", "update", "encrypt" });
		}
	}
	
	return all_results;
}


double time_op(Duration runtime, void delegate() op)
{
	StopWatch sw;
	sw.start();
	int reps = 0;
	while(sw.peek().to!Duration < runtime)
	{
		op();
		++reps;
	}
	sw.stop();
	return reps.to!double / sw.peek().seconds.to!double; // ie, return ops per second
}

package	double find_first_in(in HashMap!(string, double) m,
	                     		const ref Vector!string keys)
{
	foreach (key; keys)
	{
		auto i = m.find(key);
		if (i != m.end())
			return i.second;
	}
	
	throw new Exception("algorithm_factory no usable keys found in result");
}
