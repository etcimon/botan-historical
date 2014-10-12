/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.prf_tls;
import botan.internal.xor_buf;
import botan.hmac;
import botan.md5;
import botan.sha160;
namespace {

/*
* TLS PRF P_hash function
*/
void P_hash(SafeVector!ubyte output,
				MessageAuthenticationCode& mac,
				in ubyte* secret, size_t secret_len,
				in ubyte* seed, size_t seed_len)
{
	try
	{
		mac.set_key(secret, secret_len);
	}
	catch(Invalid_Key_Length)
	{
		throw new Internal_Error("The premaster secret of " ~
									std.conv.to!string(secret_len) +
									" bytes is too long for the PRF");
	}

	SafeVector!ubyte A(seed, seed + seed_len);

	size_t offset = 0;

	while(offset != output.size())
	{
		const size_t this_block_len =
			std.algorithm.min(mac.output_length(), output.size() - offset);

		A = mac.process(A);

		mac.update(A);
		mac.update(seed, seed_len);
		SafeVector!ubyte block = mac.flush();

		xor_buf(&output[offset], &block[0], this_block_len);
		offset += this_block_len;
	}
}

}

/*
* TLS PRF Constructor and Destructor
*/
TLS_PRF::TLS_PRF()
{
	hmac_md5.reset(new HMAC(new MD5));
	hmac_sha1.reset(new HMAC(new SHA_160));
}

/*
* TLS PRF
*/
SafeVector!ubyte TLS_PRF::derive(size_t key_len,
											  in ubyte* secret, size_t secret_len,
											  in ubyte* seed, size_t seed_len) const
{
	SafeVector!ubyte output = SafeVector!ubyte(key_len);

	size_t S1_len = (secret_len + 1) / 2,
			 S2_len = (secret_len + 1) / 2;
	const ubyte* S1 = secret;
	const ubyte* S2 = secret + (secret_len - S2_len);

	P_hash(output, *hmac_md5,  S1, S1_len, seed, seed_len);
	P_hash(output, *hmac_sha1, S2, S2_len, seed, seed_len);

	return output;
}

/*
* TLS v1.2 PRF Constructor and Destructor
*/
TLS_12_PRF::TLS_12_PRF(MessageAuthenticationCode mac) : hmac(mac)
{
}

SafeVector!ubyte TLS_12_PRF::derive(size_t key_len,
												  in ubyte* secret, size_t secret_len,
												  in ubyte* seed, size_t seed_len) const
{
	SafeVector!ubyte output = SafeVector!ubyte(key_len);

	P_hash(output, *hmac, secret, secret_len, seed, seed_len);

	return output;
}

}
