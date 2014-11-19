#include "tests.h"

#include <botan/auto_rng.h>
#include <iostream>

#if defined(BOTAN_HAS_CRYPTO_BOX)
  #include <botan/cryptobox.h>
#endif

using namespace Botan;

size_t test_cryptobox()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_CRYPTO_BOX)
	AutoSeeded_RNG rng;

	__gshared immutable ubyte[3] msg = [ 0xAA, 0xBB, 0xCC ];
	string ciphertext = CryptoBox::encrypt(msg.ptr, msg.length, "secret password", rng);

	try
	{
		string plaintext = CryptoBox::decrypt(ciphertext, "secret password");

		if(plaintext.length != msg.length || !same_mem(cast(const ubyte*)(&plaintext[0]), msg.ptr, msg.length))
			++fails;

	}
	catch(Exception e)
	{
		writeln("Error during Cryptobox test " ~ e.msg);
		++fails;
	}

	test_report("Cryptobox", 1, fails);
#endif

	return fails;
}