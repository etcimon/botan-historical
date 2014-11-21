/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.prf.hkdf;

import botan.constants;
static if (BOTAN_HAS_HKDF):

import botan.mac.mac;
import botan.hash.hash;
import botan.utils.types;

/**
* HKDF, see @rfc 5869 for details
*/
final class HKDF
{
public:
	this(MessageAuthenticationCode extractor,
		  MessageAuthenticationCode prf) 
	{
		m_extractor = extractor;
		m_prf = prf;
	}

	this(MessageAuthenticationCode prf)
	{
		m_extractor = prf;
		m_prf = m_extractor.clone(); 
	}

	void start_extract(in ubyte* salt, size_t salt_len)
	{
		m_extractor.set_key(salt, salt_len);
	}

	void extract(in ubyte* input, size_t input_len)
	{
		m_extractor.update(input, input_len);
	}

	void finish_extract()
	{
		m_prf.set_key(m_extractor.flush());
	}


	/**
	* Only call after extract
	* @param output_len must be less than 256*hashlen
	*/
	void expand(ubyte* output, size_t output_len,
	            in ubyte* info, size_t info_len)
	{
		if (output_len > m_prf.output_length * 255)
			throw new Invalid_Argument("HKDF requested output too large");
		
		ubyte counter = 1;
		
		Secure_Vector!ubyte T;
		
		while (output_len)
		{
			m_prf.update(T);
			m_prf.update(info, info_len);
			m_prf.update(counter++);
			T = m_prf.flush();
			
			const size_t to_write = std.algorithm.min(T.length, output_len);
			copy_mem(output.ptr, T.ptr, to_write);
			output += to_write;
			output_len -= to_write;
		}
	}


	@property string name() const
	{
		return "HKDF(" ~ m_prf.name ~ ")";
	}

	void clear()
	{
		m_extractor.clear();
		m_prf.clear();
	}
private:
	Unique!MessageAuthenticationCode m_extractor;
	Unique!MessageAuthenticationCode m_prf;
}


static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.libstate;

private __gshared size_t total_tests;

Secure_Vector!ubyte hkdf(string hkdf_algo,
                         in Secure_Vector!ubyte ikm,
                         in Secure_Vector!ubyte salt,
                         in Secure_Vector!ubyte info,
                         size_t L)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	
	const string algo = hkdf_algo[5 .. hkdf_algo.length-6+5];
	
	const MessageAuthenticationCode mac_proto = af.prototype_mac("HMAC(" ~ algo ~ ")");
	
	if (!mac_proto)
		throw new Invalid_Argument("Bad HKDF hash '" ~ algo ~ "'");
	
	HKDF hkdf = scoped!HKDF(mac_proto.clone(), mac_proto.clone());
	
	hkdf.start_extract(&salt[0], salt.length);
	hkdf.extract(&ikm[0], ikm.length);
	hkdf.finish_extract();
	
	Secure_Vector!ubyte key = Secure_Vector!ubyte(L);
	hkdf.expand(&key[0], key.length, &info[0], info.length);
	return key;
}

size_t hkdf_test(string algo, string ikm, string salt, string info, string okm, size_t L)
{
	import core.atomic;
	atomicOp!"+="(total_tests, 1);
	const string got = hex_encode(hkdf(algo, 
	                                   hex_decode_locked(ikm), 
	                                   hex_decode_locked(salt), 
	                                   hex_decode_locked(info),
	                                   L));
	
	if (got != okm)
	{
		writeln("HKDF got " ~ got ~ " expected " ~ okm);
		return 1;
	}
	
	return 0;
}

unittest
{
	File vec = File("test_data/hkdf.vec", "r");
	
	size_t fails = run_tests_bb(vec, "HKDF", "OKM", true,
	                            (string[string] m)
	                            {
		return hkdf_test(m["HKDF"], m["IKM"], m["salt"], m["info"], m["OKM"], to!uint(m["L"]));
	});
	
	test_report("hkdf", total_tests, fails);
}
