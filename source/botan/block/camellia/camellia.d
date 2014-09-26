/*
* Camellia
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/camellia.h>
#include <botan/internal/camellia_sbox.h>
#include <botan/loadstor.h>
namespace Camellia_F {

namespace {

/*
* We use the slow byte-wise version of F in the first and last rounds
* to help protect against timing attacks
*/
ulong F_SLOW(ulong v, ulong K)
{
	static const byte SBOX[256] = {
		0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57,
		0x35, 0xEA, 0x0C, 0xAE, 0x41, 0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19,
		0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD, 0x86,
		0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F,
		0x5E, 0xC5, 0x0B, 0x1A, 0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D,
		0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D, 0x8B, 0x0D,
		0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0,
		0xB1, 0x84, 0x99, 0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05,
		0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7, 0x14, 0x58, 0x3A,
		0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18,
		0xF2, 0x22, 0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24,
		0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50, 0xAA, 0xD0, 0xA0, 0x7D,
		0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64,
		0xD2, 0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03,
		0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94, 0x87, 0x5C, 0x83, 0x02, 0xCD,
		0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
		0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F,
		0x4B, 0x13, 0xBE, 0x63, 0x2E, 0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E,
		0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59, 0x78,
		0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42,
		0x88, 0xA2, 0x8D, 0xFA, 0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC,
		0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4, 0x40, 0x28,
		0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77,
		0xC7, 0x80, 0x9E };

	const ulong x = v ^ K;

	const byte t1 = SBOX[get_byte(0, x)];
	const byte t2 = rotate_left(SBOX[get_byte(1, x)], 1);
	const byte t3 = rotate_left(SBOX[get_byte(2, x)], 7);
	const byte t4 = SBOX[rotate_left(get_byte(3, x), 1)];
	const byte t5 = rotate_left(SBOX[get_byte(4, x)], 1);
	const byte t6 = rotate_left(SBOX[get_byte(5, x)], 7);
	const byte t7 = SBOX[rotate_left(get_byte(6, x), 1)];
	const byte t8 = SBOX[get_byte(7, x)];

	const byte y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
	const byte y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
	const byte y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
	const byte y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
	const byte y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
	const byte y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
	const byte y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
	const byte y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

	return make_ulong(y1, y2, y3, y4, y5, y6, y7, y8);
}

 ulong F(ulong v, ulong K)
{
	const ulong x = v ^ K;

	return Camellia_SBOX1[get_byte(0, x)] ^
			 Camellia_SBOX2[get_byte(1, x)] ^
			 Camellia_SBOX3[get_byte(2, x)] ^
			 Camellia_SBOX4[get_byte(3, x)] ^
			 Camellia_SBOX5[get_byte(4, x)] ^
			 Camellia_SBOX6[get_byte(5, x)] ^
			 Camellia_SBOX7[get_byte(6, x)] ^
			 Camellia_SBOX8[get_byte(7, x)];
}

 ulong FL(ulong v, ulong K)
{
	uint x1 = (v >> 32);
	uint x2 = (v & 0xFFFFFFFF);

	const uint k1 = (K >> 32);
	const uint k2 = (K & 0xFFFFFFFF);

	x2 ^= rotate_left(x1 & k1, 1);
	x1 ^= (x2 | k2);

	return ((cast(ulong)(x1) << 32) | x2);
}

 ulong FLINV(ulong v, ulong K)
{
	uint x1 = (v >> 32);
	uint x2 = (v & 0xFFFFFFFF);

	const uint k1 = (K >> 32);
	const uint k2 = (K & 0xFFFFFFFF);

	x1 ^= (x2 | k2);
	x2 ^= rotate_left(x1 & k1, 1);

	return ((cast(ulong)(x1) << 32) | x2);
}

/*
* Camellia Encryption
*/
void encrypt(byte* input, byte* output, size_t blocks,
				 const secure_vector<ulong>& SK, const size_t rounds)
{
	size_t blocks = input.length;
	for(size_t i = 0; i != blocks; ++i)
	{
		ulong D1 = load_be!ulong(input, 0);
		ulong D2 = load_be!ulong(input, 1);

		const ulong* K = &SK[0];

		D1 ^= *K++;
		D2 ^= *K++;

		D2 ^= F_SLOW(D1, *K++);
		D1 ^= F_SLOW(D2, *K++);

		for(size_t r = 1; r != rounds - 1; ++r)
		{
			if(r % 3 == 0)
			{
				D1 = FL	(D1, *K++);
				D2 = FLINV(D2, *K++);
			}

			D2 ^= F(D1, *K++);
			D1 ^= F(D2, *K++);
		}

		D2 ^= F_SLOW(D1, *K++);
		D1 ^= F_SLOW(D2, *K++);

		D2 ^= *K++;
		D1 ^= *K++;

		store_be(out, D2, D1);

		in += 16;
		out += 16;
	}
}

/*
* Camellia Decryption
*/
void decrypt(byte* input, byte* output, size_t blocks,
				 const secure_vector<ulong>& SK, const size_t rounds)
{
	size_t blocks = input.length;
	for(size_t i = 0; i != blocks; ++i)
	{
		ulong D1 = load_be!ulong(input, 0);
		ulong D2 = load_be!ulong(input, 1);

		const ulong* K = &SK[SK.size()-1];

		D2 ^= *K--;
		D1 ^= *K--;

		D2 ^= F_SLOW(D1, *K--);
		D1 ^= F_SLOW(D2, *K--);

		for(size_t r = 1; r != rounds - 1; ++r)
		{
			if(r % 3 == 0)
			{
				D1 = FL	(D1, *K--);
				D2 = FLINV(D2, *K--);
			}

			D2 ^= F(D1, *K--);
			D1 ^= F(D2, *K--);
		}

		D2 ^= F_SLOW(D1, *K--);
		D1 ^= F_SLOW(D2, *K--);

		D1 ^= *K--;
		D2 ^= *K;

		store_be(out, D2, D1);

		in += 16;
		out += 16;
	}
}

ulong left_rot_hi(ulong h, ulong l, size_t shift)
{
	return (h << shift) | ((l >> (64-shift)));
}

ulong left_rot_lo(ulong h, ulong l, size_t shift)
{
	return (h >> (64-shift)) | (l << shift);
}

/*
* Camellia Key Schedule
*/
void key_schedule(secure_vector<ulong>& SK, in byte* key)
{
	const ulong Sigma1 = 0xA09E667F3BCC908B;
	const ulong Sigma2 = 0xB67AE8584CAA73B2;
	const ulong Sigma3 = 0xC6EF372FE94F82BE;
	const ulong Sigma4 = 0x54FF53A5F1D36F1C;
	const ulong Sigma5 = 0x10E527FADE682D1D;
	const ulong Sigma6 = 0xB05688C2B3E6C1FD;

	const ulong KL_H = load_be!ulong(key, 0);
	const ulong KL_L = load_be!ulong(key, 1);

	const ulong KR_H = (length >= 24) ? load_be!ulong(key, 2) : 0;
	const ulong KR_L =
		(length == 32) ? load_be!ulong(key, 3) : ((length == 24) ? ~KR_H : 0);

	ulong D1 = KL_H ^ KR_H;
	ulong D2 = KL_L ^ KR_L;
	D2 ^= F(D1, Sigma1);
	D1 ^= F(D2, Sigma2);
	D1 ^= KL_H;
	D2 ^= KL_L;
	D2 ^= F(D1, Sigma3);
	D1 ^= F(D2, Sigma4);

	const ulong KA_H = D1;
	const ulong KA_L = D2;

	D1 = KA_H ^ KR_H;
	D2 = KA_L ^ KR_L;
	D2 ^= F(D1, Sigma5);
	D1 ^= F(D2, Sigma6);

	const ulong KB_H = D1;
	const ulong KB_L = D2;

	if(length == 16)
	{
		SK.resize(26);

		SK[ 0] = KL_H;
		SK[ 1] = KL_L;
		SK[ 2] = KA_H;
		SK[ 3] = KA_L;
		SK[ 4] = left_rot_hi(KL_H, KL_L, 15);
		SK[ 5] = left_rot_lo(KL_H, KL_L, 15);
		SK[ 6] = left_rot_hi(KA_H, KA_L, 15);
		SK[ 7] = left_rot_lo(KA_H, KA_L, 15);
		SK[ 8] = left_rot_hi(KA_H, KA_L, 30);
		SK[ 9] = left_rot_lo(KA_H, KA_L, 30);
		SK[10] = left_rot_hi(KL_H, KL_L, 45);
		SK[11] = left_rot_lo(KL_H, KL_L, 45);
		SK[12] = left_rot_hi(KA_H, KA_L,  45);
		SK[13] = left_rot_lo(KL_H, KL_L,  60);
		SK[14] = left_rot_hi(KA_H, KA_L,  60);
		SK[15] = left_rot_lo(KA_H, KA_L,  60);
		SK[16] = left_rot_lo(KL_H, KL_L,  77-64);
		SK[17] = left_rot_hi(KL_H, KL_L,  77-64);
		SK[18] = left_rot_lo(KL_H, KL_L,  94-64);
		SK[19] = left_rot_hi(KL_H, KL_L,  94-64);
		SK[20] = left_rot_lo(KA_H, KA_L,  94-64);
		SK[21] = left_rot_hi(KA_H, KA_L,  94-64);
		SK[22] = left_rot_lo(KL_H, KL_L, 111-64);
		SK[23] = left_rot_hi(KL_H, KL_L, 111-64);
		SK[24] = left_rot_lo(KA_H, KA_L, 111-64);
		SK[25] = left_rot_hi(KA_H, KA_L, 111-64);
	}
	else
	{
		SK.resize(34);

		SK[ 0] = KL_H;
		SK[ 1] = KL_L;
		SK[ 2] = KB_H;
		SK[ 3] = KB_L;

		SK[ 4] = left_rot_hi(KR_H, KR_L, 15);
		SK[ 5] = left_rot_lo(KR_H, KR_L, 15);
		SK[ 6] = left_rot_hi(KA_H, KA_L, 15);
		SK[ 7] = left_rot_lo(KA_H, KA_L, 15);

		SK[ 8] = left_rot_hi(KR_H, KR_L, 30);
		SK[ 9] = left_rot_lo(KR_H, KR_L, 30);
		SK[10] = left_rot_hi(KB_H, KB_L, 30);
		SK[11] = left_rot_lo(KB_H, KB_L, 30);

		SK[12] = left_rot_hi(KL_H, KL_L, 45);
		SK[13] = left_rot_lo(KL_H, KL_L, 45);
		SK[14] = left_rot_hi(KA_H, KA_L, 45);
		SK[15] = left_rot_lo(KA_H, KA_L, 45);

		SK[16] = left_rot_hi(KL_H, KL_L, 60);
		SK[17] = left_rot_lo(KL_H, KL_L, 60);
		SK[18] = left_rot_hi(KR_H, KR_L, 60);
		SK[19] = left_rot_lo(KR_H, KR_L, 60);
		SK[20] = left_rot_hi(KB_H, KB_L, 60);
		SK[21] = left_rot_lo(KB_H, KB_L, 60);

		SK[22] = left_rot_lo(KL_H, KL_L,  77-64);
		SK[23] = left_rot_hi(KL_H, KL_L,  77-64);
		SK[24] = left_rot_lo(KA_H, KA_L,  77-64);
		SK[25] = left_rot_hi(KA_H, KA_L,  77-64);

		SK[26] = left_rot_lo(KR_H, KR_L,  94-64);
		SK[27] = left_rot_hi(KR_H, KR_L,  94-64);
		SK[28] = left_rot_lo(KA_H, KA_L,  94-64);
		SK[29] = left_rot_hi(KA_H, KA_L,  94-64);
		SK[30] = left_rot_lo(KL_H, KL_L, 111-64);
		SK[31] = left_rot_hi(KL_H, KL_L, 111-64);
		SK[32] = left_rot_lo(KB_H, KB_L, 111-64);
		SK[33] = left_rot_hi(KB_H, KB_L, 111-64);
	}
}

}

}

void Camellia_128::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::encrypt(input, out, blocks, SK, 9);
}

void Camellia_192::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::encrypt(input, out, blocks, SK, 12);
}

void Camellia_256::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::encrypt(input, out, blocks, SK, 12);
}

void Camellia_128::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::decrypt(input, out, blocks, SK, 9);
}

void Camellia_192::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::decrypt(input, out, blocks, SK, 12);
}

void Camellia_256::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	Camellia_F::decrypt(input, out, blocks, SK, 12);
}

void Camellia_128::key_schedule(in byte* key)
{
	Camellia_F::key_schedule(SK, key, length);
}

void Camellia_192::key_schedule(in byte* key)
{
	Camellia_F::key_schedule(SK, key, length);
}

void Camellia_256::key_schedule(in byte* key)
{
	Camellia_F::key_schedule(SK, key, length);
}

void Camellia_128::clear()
{
	zap(SK);
}

void Camellia_192::clear()
{
	zap(SK);
}

void Camellia_256::clear()
{
	zap(SK);
}

}
