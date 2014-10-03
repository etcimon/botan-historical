/*
* Blowfish
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.blowfish;
import botan.loadstor;
/*
* Blowfish Encryption
*/
void Blowfish::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	const uint* S1 = &S[0];
	const uint* S2 = &S[256];
	const uint* S3 = &S[512];
	const uint* S4 = &S[768];

	for (size_t i = 0; i != blocks; ++i)
	{
		uint L = load_be!uint(input, 0);
		uint R = load_be!uint(input, 1);

		for (size_t j = 0; j != 16; j += 2)
		{
			L ^= P[j];
			R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
					 S3[get_byte(2, L)]) + S4[get_byte(3, L)];

			R ^= P[j+1];
			L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
					 S3[get_byte(2, R)]) + S4[get_byte(3, R)];
		}

		L ^= P[16]; R ^= P[17];

		store_be(output, R, L);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* Blowfish Decryption
*/
void Blowfish::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	const uint* S1 = &S[0];
	const uint* S2 = &S[256];
	const uint* S3 = &S[512];
	const uint* S4 = &S[768];

	for (size_t i = 0; i != blocks; ++i)
	{
		uint L = load_be!uint(input, 0);
		uint R = load_be!uint(input, 1);

		for (size_t j = 17; j != 1; j -= 2)
		{
			L ^= P[j];
			R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
					 S3[get_byte(2, L)]) + S4[get_byte(3, L)];

			R ^= P[j-1];
			L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
					 S3[get_byte(2, R)]) + S4[get_byte(3, R)];
		}

		L ^= P[1]; R ^= P[0];

		store_be(output, R, L);

		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* Blowfish Key Schedule
*/
void Blowfish::key_schedule(in byte* key)
{
	P.resize(18);
	std::copy(P_INIT, P_INIT + 18, P.begin());

	S.resize(1024);
	std::copy(S_INIT, S_INIT + 1024, S.begin());

	immutable byte[16] null_salt = { 0 };

	key_expansion(key, length, null_salt);
}

void Blowfish::key_expansion(in byte* key,
									  size_t length,
									  in byte[16] salt)
{
	for (size_t i = 0, j = 0; i != 18; ++i, j += 4)
		P[i] ^= make_uint(key[(j  ) % length], key[(j+1) % length],
								  key[(j+2) % length], key[(j+3) % length]);

	uint L = 0, R = 0;
	generate_sbox(P, L, R, salt, 0);
	generate_sbox(S, L, R, salt, 2);
}

/*
* Modified key schedule used for bcrypt password hashing
*/
void Blowfish::eks_key_schedule(in byte* key, size_t length,
										  in byte[16] salt, size_t workfactor)
{
	// Truncate longer passwords to the 56 byte limit Blowfish enforces
	length = std.algorithm.min<size_t>(length, 55);

	if (workfactor == 0)
		throw new std::invalid_argument("Bcrypt work factor must be at least 1");

	/*
	* On a 2.8 GHz Core-i7, workfactor == 18 takes about 25 seconds to
	* hash a password. This seems like a reasonable upper bound for the
	* time being.
	*/
	if (workfactor > 18)
		throw new std::invalid_argument("Requested Bcrypt work factor " +
											 std::to_string(workfactor) + " too large");

	P.resize(18);
	std::copy(P_INIT, P_INIT + 18, P.begin());

	S.resize(1024);
	std::copy(S_INIT, S_INIT + 1024, S.begin());

	key_expansion(key, length, salt);

	const byte[16] null_salt = { 0 };
	const size_t rounds = 1 << workfactor;

	for (size_t r = 0; r != rounds; ++r)
	{
		key_expansion(key, length, null_salt);
		key_expansion(salt, 16, null_salt);
	}
}

/*
* Generate one of the Sboxes
*/
void Blowfish::generate_sbox(secure_vector!uint& box,
									  ref uint L, ref uint R,
									  in byte[16] salt,
									  size_t salt_off) const
{
	const uint* S1 = &S[0];
	const uint* S2 = &S[256];
	const uint* S3 = &S[512];
	const uint* S4 = &S[768];

	for (size_t i = 0; i != box.size(); i += 2)
	{
		L ^= load_be!uint(salt, (i + salt_off) % 4);
		R ^= load_be!uint(salt, (i + salt_off + 1) % 4);

		for (size_t j = 0; j != 16; j += 2)
		{
			L ^= P[j];
			R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
					 S3[get_byte(2, L)]) + S4[get_byte(3, L)];

			R ^= P[j+1];
			L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
					 S3[get_byte(2, R)]) + S4[get_byte(3, R)];
		}

		uint T = R; R = L ^ P[16]; L = T ^ P[17];
		box[i] = L;
		box[i+1] = R;
	}
}

/*
* Clear memory of sensitive data
*/
void Blowfish::clear()
{
	zap(P);
	zap(S);
}

}
