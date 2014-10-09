/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pbkdf;
import stdexcept;
OctetString PBKDF::derive_key(size_t output_len,
										in string passphrase,
										in ubyte* salt, size_t salt_len,
										size_t iterations) const
{
	if (iterations == 0)
		throw new Invalid_Argument(name() ~ ": Invalid iteration count");

	auto derived = key_derivation(output_len, passphrase,
											salt, salt_len, iterations,
											std::chrono::milliseconds(0));

	BOTAN_ASSERT(derived.first == iterations,
					 "PBKDF used the correct number of iterations");

	return derived.second;
}

OctetString PBKDF::derive_key(size_t output_len,
										in string passphrase,
										in ubyte* salt, size_t salt_len,
										std::chrono::milliseconds ms,
										size_t& iterations) const
{
	auto derived = key_derivation(output_len, passphrase, salt, salt_len, 0, ms);

	iterations = derived.first;

	return derived.second;
}

}
