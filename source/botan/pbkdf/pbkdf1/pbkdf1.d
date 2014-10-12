/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pbkdf1;
import botan.utils.exceptn;
/*
* Return a PKCS#5 PBKDF1 derived key
*/
Pair!(size_t, OctetString)
PKCS5_PBKDF1::key_derivation(size_t key_len,
									  in string passphrase,
									  in ubyte* salt, size_t salt_len,
									  size_t iterations,
									  std::chrono::milliseconds msec) const
{
	if (key_len > hash.output_length())
		throw new Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");

	hash.update(passphrase);
	hash.update(salt, salt_len);
	SafeVector!ubyte key = hash.flush();

	const auto start = Clock.currTime();
	size_t iterations_performed = 1;

	while(true)
	{
		if (iterations == 0)
		{
			if (iterations_performed % 10000 == 0)
			{
				auto time_taken = Clock.currTime() - start;
				auto msec_taken = std::chrono::duration_cast(<std::chrono::milliseconds>)(time_taken);
				if (msec_taken > msec)
					break;
			}
		}
		else if (iterations_performed == iterations)
			break;

		hash.update(key);
		hash.flushInto(&key[0]);

		++iterations_performed;
	}

	return Pair(iterations_performed,
								 OctetString(&key[0], std.algorithm.min(key_len, key.size())));
}

}
