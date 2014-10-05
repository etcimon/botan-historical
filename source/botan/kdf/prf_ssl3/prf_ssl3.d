/*
* SSLv3 PRF
* (C) 2004-2006 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.prf_ssl3;
import botan.algo_base.symkey;
import botan.exceptn;
import botan.sha160;
import botan.md5;
namespace {

/*
* Return the next inner hash
*/
OctetString next_hash(size_t where, size_t want,
							 HashFunction& md5, HashFunction& sha1,
							 in ubyte* secret, size_t secret_len,
							 in ubyte* seed, size_t seed_len)
{
	BOTAN_ASSERT(want <= md5.output_length(),
					 "Output size producable by MD5");

	const ubyte ASCII_A_CHAR = 0x41;

	for (size_t j = 0; j != where + 1; j++)
	  sha1.update(cast(ubyte)(ASCII_A_CHAR + where));
	sha1.update(secret, secret_len);
	sha1.update(seed, seed_len);
	SafeVector!ubyte sha1_hash = sha1.flush();

	md5.update(secret, secret_len);
	md5.update(sha1_hash);
	SafeVector!ubyte md5_hash = md5.flush();

	return OctetString(&md5_hash[0], want);
}

}

/*
* SSL3 PRF
*/
SafeVector!ubyte SSL3_PRF::derive(size_t key_len,
												in ubyte* secret, size_t secret_len,
												in ubyte* seed, size_t seed_len) const
{
	if (key_len > 416)
		throw new Invalid_Argument("SSL3_PRF: Requested key length is too large");

	MD5 md5;
	SHA_160 sha1;

	OctetString output;

	int counter = 0;
	while(key_len)
	{
		const size_t produce = std.algorithm.min<size_t>(key_len, md5.output_length());

		output = output + next_hash(counter++, produce, md5, sha1,
											 secret, secret_len, seed, seed_len);

		key_len -= produce;
	}

	return output.bits_of();
}

}
