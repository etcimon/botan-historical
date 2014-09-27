/*
* RTSS (threshold secret sharing)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/tss.h>
#include <botan/loadstor.h>
#include <botan/pipe.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/sha160.h>
namespace {

/**
Table for GF(2^8) arithmetic (exponentials)
*/
const byte[256] RTSS_EXP = {
0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72,
0x96, 0xA1, 0xF8, 0x13, 0x35, 0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73,
0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA, 0xE5,
0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70,
0x90, 0xAB, 0xE6, 0x31, 0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44,
0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD, 0x4C, 0xD4,
0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18,
0x28, 0x78, 0x88, 0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F,
0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A, 0xB5, 0xC4, 0x57,
0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6,
0x61, 0xA3, 0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F,
0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0, 0xFB, 0x16, 0x3A, 0x4E,
0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F,
0x41, 0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED,
0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75, 0x9F, 0xBA, 0xD5, 0x64, 0xAC,
0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80,
0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F,
0xB1, 0xC8, 0x43, 0xC5, 0x54, 0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4,
0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA, 0x45,
0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42,
0xC6, 0x51, 0xF3, 0x0E, 0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D,
0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17, 0x39, 0x4B,
0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7,
0x52, 0xF6, 0x01 };

/**
Table for GF(2^8) arithmetic (logarithms)
*/
const byte[] RTSS_LOG = {
0x90, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B,
0x68, 0x33, 0xEE, 0xDF, 0x03, 0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D,
0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1, 0x7D,
0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72,
0x9A, 0xC9, 0x09, 0x78, 0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1,
0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E, 0x96, 0x8F,
0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40,
0x46, 0x83, 0x38, 0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62,
0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10, 0x7E, 0x6E, 0x48,
0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85,
0x3D, 0xBA, 0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E,
0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57, 0xAF, 0x58, 0xA8, 0x50,
0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD,
0xE8, 0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB,
0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0, 0x7F, 0x0C, 0xF6, 0x6F, 0x17,
0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7,
0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1,
0x6C, 0xAA, 0x55, 0x29, 0x9D, 0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE,
0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1, 0x53,
0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D,
0x56, 0xF2, 0xD3, 0xAB, 0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E,
0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5, 0x67, 0x4A,
0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0,
0xF7, 0x70, 0x07 };

byte gfp_mul(byte x, byte y)
{
	if (x == 0 || y == 0)
		return 0;
	return RTSS_EXP[(RTSS_LOG[x] + RTSS_LOG[y]) % 255];
}

byte rtss_hash_id(in string hash_name)
{
	if (hash_name == "SHA-160")
		return 1;
	else if (hash_name == "SHA-256")
		return 2;
	else
		throw new Invalid_Argument("RTSS only supports SHA-1 and SHA-256");
}

HashFunction* get_rtss_hash_by_id(byte id)
{
	if (id == 1)
		return new SHA_160;
	else if (id == 2)
		return new SHA_256;
	else
		throw new Decoding_Error("Bad RTSS hash identifier");
}

}

RTSS_Share::RTSS_Share(in string hex_input)
{
	contents = hex_decode_locked(hex_input);
}

byte RTSS_Share::share_id() const
{
	if (!initialized())
		throw new Invalid_State("RTSS_Share::share_id not initialized");

	return contents[20];
}

string RTSS_Share::to_string() const
{
	return hex_encode(&contents[0], contents.size());
}

Vector!( RTSS_Share )
RTSS_Share::split(byte M, byte N,
						in byte* S, ushort S_len,
						const byte identifier[16],
						RandomNumberGenerator& rng)
{
	if (M == 0 || N == 0 || M > N)
		throw new Encoding_Error("RTSS_Share::split: M == 0 or N == 0 or M > N");

	SHA_256 hash; // always use SHA-256 when generating shares

	Vector!( RTSS_Share ) shares(N);

	// Create RTSS header in each share
	for (byte i = 0; i != N; ++i)
	{
		shares[i].contents += Pair(identifier, 16);
		shares[i].contents += rtss_hash_id(hash.name());
		shares[i].contents += M;
		shares[i].contents += get_byte(0, S_len);
		shares[i].contents += get_byte(1, S_len);
	}

	// Choose sequential values for X starting from 1
	for (byte i = 0; i != N; ++i)
		shares[i].contents.push_back(i+1);

	// secret = S || H(S)
	SafeVector!byte secret(S, S + S_len);
	secret += hash.process(S, S_len);

	for (size_t i = 0; i != secret.size(); ++i)
	{
		Vector!( byte ) coefficients(M-1);
		rng.randomize(&coefficients[0], coefficients.size());

		for (byte j = 0; j != N; ++j)
		{
			const byte X = j + 1;

			byte sum = secret[i];
			byte X_i = X;

			for (size_t k = 0; k != coefficients.size(); ++k)
			{
				sum ^= gfp_mul(X_i, coefficients[k]);
				X_i  = gfp_mul(X_i, X);
			}

			shares[j].contents.push_back(sum);
		}
	}

	return shares;
}

SafeVector!byte
RTSS_Share::reconstruct(in Vector!( RTSS_Share ) shares)
{
	const size_t RTSS_HEADER_SIZE = 20;

	for (size_t i = 0; i != shares.size(); ++i)
	{
		if (shares[i].size() != shares[0].size())
			throw new Decoding_Error("Different sized RTSS shares detected");
		if (shares[i].share_id() == 0)
			throw new Decoding_Error("Invalid (id = 0) RTSS share detected");
		if (shares[i].size() < RTSS_HEADER_SIZE)
			throw new Decoding_Error("Missing or malformed RTSS header");

		if (!same_mem(&shares[0].contents[0],
						 &shares[i].contents[0], RTSS_HEADER_SIZE))
			throw new Decoding_Error("Different RTSS headers detected");
	}

	if (shares.size() < shares[0].contents[17])
		throw new Decoding_Error("Insufficient shares to do TSS reconstruction");

	ushort secret_len = make_ushort(shares[0].contents[18],
											  shares[0].contents[19]);

	byte hash_id = shares[0].contents[16];

	std::unique_ptr<HashFunction> hash(get_rtss_hash_by_id(hash_id));

	if (shares[0].size() != secret_len + hash->output_length() + RTSS_HEADER_SIZE + 1)
		throw new Decoding_Error("Bad RTSS length field in header");

	Vector!( byte ) V(shares.size());
	SafeVector!byte secret;

	for (size_t i = RTSS_HEADER_SIZE + 1; i != shares[0].size(); ++i)
	{
		for (size_t j = 0; j != V.size(); ++j)
			V[j] = shares[j].contents[i];

		byte r = 0;
		for (size_t k = 0; k != shares.size(); ++k)
		{
			// L_i function:
			byte r2 = 1;
			for (size_t l = 0; l != shares.size(); ++l)
			{
				if (k == l)
					continue;

				byte share_k = shares[k].share_id();
				byte share_l = shares[l].share_id();

				if (share_k == share_l)
					throw new Decoding_Error("Duplicate shares found in RTSS recovery");

				byte div = RTSS_EXP[(255 +
											RTSS_LOG[share_l] -
											RTSS_LOG[share_k ^ share_l]) % 255];

				r2 = gfp_mul(r2, div);
			}

			r ^= gfp_mul(V[k], r2);
		}
		secret.push_back(r);
	}

	if (secret.size() != secret_len + hash->output_length())
		throw new Decoding_Error("Bad length in RTSS output");

	hash->update(&secret[0], secret_len);
	SafeVector!byte hash_check = hash->flush();

	if (!same_mem(&hash_check[0],
					 &secret[secret_len], hash->output_length()))
		throw new Decoding_Error("RTSS hash check failed");

	return SafeVector!byte(&secret[0], &secret[secret_len]);
}

}
