/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pbkdf2;
import botan.utils.get_byte;
import botan.internal.xor_buf;
import botan.utils.rounding;
/*
* Return a PKCS #5 PBKDF2 derived key
*/
Pair!(size_t, OctetString)
PKCS5_PBKDF2::key_derivation(size_t key_len,
									  in string passphrase,
									  in ubyte* salt, size_t salt_len,
									  size_t iterations,
									  std::chrono::milliseconds msec) const
{
	if (key_len == 0)
		return Pair(iterations, OctetString());

	try
	{
		mac.set_key(cast(const ubyte*)(passphrase.data()),
						 passphrase.length());
	}
	catch(Invalid_Key_Length)
	{
		throw new Exception(name() ~ " cannot accept passphrases of length " ~
							 std.conv.to!string(passphrase.length()));
	}

	SafeVector!ubyte key(key_len);

	ubyte* T = &key[0];

	SafeVector!ubyte U(mac.output_length());

	const size_t blocks_needed = round_up(key_len, mac.output_length()) / mac.output_length();

	std::chrono::microseconds usec_per_block =
		std::chrono::duration_cast(<std::chrono::microseconds>)(msec) / blocks_needed;

	uint counter = 1;
	while(key_len)
	{
		size_t T_size = std.algorithm.min(mac.output_length(), key_len);

		mac.update(salt, salt_len);
		mac.update_be(counter);
		mac.flushInto(&U[0]);

		xor_buf(T, &U[0], T_size);

		if (iterations == 0)
		{
			/*
			If no iterations set, run the first block to calibrate based
			on how long hashing takes on whatever machine we're running on.
			*/

			const auto start = Clock.currTime();

			iterations = 1; // the first iteration we did above

			while(true)
			{
				mac.update(U);
				mac.flushInto(&U[0]);
				xor_buf(T, &U[0], T_size);
				iterations++;

				/*
				Only break on relatively 'even' iterations. For one it
				avoids confusion, and likely some broken implementations
				break on getting completely randomly distributed values
				*/
				if (iterations % 10000 == 0)
				{
					auto time_taken = Clock.currTime() - start;
					auto usec_taken = std::chrono::duration_cast(<std::chrono::microseconds>)(time_taken);
					if (usec_taken > usec_per_block)
						break;
				}
			}
		}
		else
		{
			for (size_t i = 1; i != iterations; ++i)
			{
				mac.update(U);
				mac.flushInto(&U[0]);
				xor_buf(T, &U[0], T_size);
			}
		}

		key_len -= T_size;
		T += T_size;
		++counter;
	}

	return Pair(iterations, key);
}

}
