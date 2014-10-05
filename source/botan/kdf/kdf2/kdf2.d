/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.kdf2;
/*
* KDF2 Key Derivation Mechanism
*/
SafeVector!ubyte KDF2::derive(size_t out_len,
										  in ubyte* secret, size_t secret_len,
										  in ubyte* P, size_t P_len) const
{
	SafeVector!ubyte output;
	uint counter = 1;

	while(out_len && counter)
	{
		hash.update(secret, secret_len);
		hash.update_be(counter);
		hash.update(P, P_len);

		SafeVector!ubyte hash_result = hash.flush();

		size_t added = std.algorithm.min(hash_result.size(), out_len);
		output += Pair(&hash_result[0], added);
		out_len -= added;

		++counter;
	}

	return output;
}

}
