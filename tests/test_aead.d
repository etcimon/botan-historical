#include "tests.h"

#include <botan/hex.h>
#include <botan/aead.h>
#include <iostream>
#include <fstream>
#include <memory>

using namespace Botan;

namespace {

size_t aead_test(string algo,
					  string input,
					  string expected,
					  string nonce_hex,
					  string ad_hex,
					  string key_hex)
{
	const auto nonce = hex_decode_locked(nonce_hex);
	const auto ad = hex_decode_locked(ad_hex);
	const auto key = hex_decode_locked(key_hex);

	std::unique_ptr<Cipher_Mode> enc(get_aead(algo, ENCRYPTION));
	std::unique_ptr<Cipher_Mode> dec(get_aead(algo, DECRYPTION));

	if(!enc || !dec)
		throw new Exception("Unknown AEAD " + algo);

	enc.set_key(key);
	dec.set_key(key);

	if(auto aead_enc = cast(AEAD_Mode)(enc.get()))
		aead_enc.set_associated_data_vec(ad);
	if(auto aead_dec = cast(AEAD_Mode)(dec.get()))
		aead_dec.set_associated_data_vec(ad);

	size_t fail = 0;

	const auto pt = hex_decode_locked(input);
	const auto expected_ct = hex_decode_locked(expected);

	auto vec = pt;
	enc.start_vec(nonce);
	// should first update if possible
	enc.finish(vec);

	if(vec != expected_ct)
	{
		writeln(algo ~ " got ct " ~ hex_encode(vec) ~ " expected " ~ expected);
		writeln(algo ~ " \n");
		++fail;
	}

	vec = expected_ct;

	dec.start_vec(nonce);
	dec.finish(vec);

	if(vec != pt)
	{
		writeln(algo ~ " got pt " ~ hex_encode(vec) ~ " expected " ~ input);
		++fail;
	}

	if(enc.authenticated())
	{
		vec = expected_ct;
		vec[0] ^= 1;
		dec.start_vec(nonce);
		try
		{
			dec.finish(vec);
			writeln(algo ~ " accepted message with modified message");
			++fail;
		}
		catch(...) {}

		if(nonce.length)
		{
			auto bad_nonce = nonce;
			bad_nonce[0] ^= 1;
			vec = expected_ct;

			dec.start_vec(bad_nonce);

			try
			{
				dec.finish(vec);
				writeln(algo ~ " accepted message with modified nonce");
				++fail;
			}
			catch(...) {}
		}

		if(auto aead_dec = cast(AEAD_Mode)(dec.get()))
		{
			auto bad_ad = ad;

			if(ad.length)
				bad_ad[0] ^= 1;
			else
				bad_ad.push_back(0);

			aead_dec.set_associated_data_vec(bad_ad);

			vec = expected_ct;
			dec.start_vec(nonce);

			try
			{
				dec.finish(vec);
				writeln(algo ~ " accepted message with modified AD");
				++fail;
			}
			catch(...) {}
		}
	}

	return fail;
}

}

size_t test_aead()
{
	auto test = [](string input)
	{
		File vec(input);

		return run_tests_bb(vec, "AEAD", "Out", true,
				 (string[string] m)
				 {
				 return aead_test(m["AEAD"], m["In"], m["Out"],
										m["Nonce"], m["AD"], m["Key"]);
				 });
	};

	return run_tests_in_dir(TEST_DATA_DIR "aead", test);
}
