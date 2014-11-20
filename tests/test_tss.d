/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

#include <botan/tss.h>

size_t test_tss()
{
	

	AutoSeeded_RNG rng;

	size_t fails = 0;

	ubyte id[16];
	for(int i = 0; i != 16; ++i)
		id[i] = i;

	const Secure_Vector!ubyte S = hex_decode_locked("7465737400");

	Vector!RTSS_Share shares = RTSS_Share.split(2, 4, &S[0], S.length, id, rng);

	auto back = RTSS_Share.reconstruct(shares);

	if (S != back)
	{
		writeln("TSS-0: " ~ hex_encode(S) ~ " != " ~ hex_encode(back));
		++fails;
	}

	shares.resize(shares.length-1);

	back = RTSS_Share.reconstruct(shares);

	if (S != back)
	{
		writeln("TSS-1: " ~ hex_encode(S) ~ " != " ~ hex_encode(back));
		++fails;
	}

	return fails;
}
#else
size_t test_tss()
{
	writeln("Skipping TSS tests");
	return 1;
}
#endif
