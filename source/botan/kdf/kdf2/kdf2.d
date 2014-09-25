/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/kdf2.h>
/*
* KDF2 Key Derivation Mechanism
*/
SafeArray!byte KDF2::derive(size_t out_len,
										  in byte[] secret, size_t secret_len,
										  in byte[] P, size_t P_len) const
{
	SafeArray!byte output;
	u32bit counter = 1;

	while(out_len && counter)
	{
		hash->update(secret, secret_len);
		hash->update_be(counter);
		hash->update(P, P_len);

		SafeArray!byte hash_result = hash->final();

		size_t added = std::min(hash_result.size(), out_len);
		output += std::make_pair(&hash_result[0], added);
		out_len -= added;

		++counter;
	}

	return output;
}

}
