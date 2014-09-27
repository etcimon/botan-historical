/*
* Keccak
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/keccak.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/rotate.h>
#include <botan/internal/xor_buf.h>
namespace {

void keccak_f_1600(ulong[25] A)
{
	static immutable ulong[24] RC = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

	for (size_t i = 0; i != 24; ++i)
	{
		immutable ulong C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
		immutable ulong C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
		immutable ulong C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
		immutable ulong C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
		immutable ulong C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

		immutable ulong D0 = rotate_left(C0, 1) ^ C3;
		immutable ulong D1 = rotate_left(C1, 1) ^ C4;
		immutable ulong D2 = rotate_left(C2, 1) ^ C0;
		immutable ulong D3 = rotate_left(C3, 1) ^ C1;
		immutable ulong D4 = rotate_left(C4, 1) ^ C2;

		immutable ulong B00 = A[ 0] ^ D1;
		immutable ulong B01 = rotate_left(A[ 6] ^ D2, 44);
		immutable ulong B02 = rotate_left(A[12] ^ D3, 43);
		immutable ulong B03 = rotate_left(A[18] ^ D4, 21);
		immutable ulong B04 = rotate_left(A[24] ^ D0, 14);
		immutable ulong B05 = rotate_left(A[ 3] ^ D4, 28);
		immutable ulong B06 = rotate_left(A[ 9] ^ D0, 20);
		immutable ulong B07 = rotate_left(A[10] ^ D1, 3);
		immutable ulong B08 = rotate_left(A[16] ^ D2, 45);
		immutable ulong B09 = rotate_left(A[22] ^ D3, 61);
		immutable ulong B10 = rotate_left(A[ 1] ^ D2, 1);
		immutable ulong B11 = rotate_left(A[ 7] ^ D3, 6);
		immutable ulong B12 = rotate_left(A[13] ^ D4, 25);
		immutable ulong B13 = rotate_left(A[19] ^ D0, 8);
		immutable ulong B14 = rotate_left(A[20] ^ D1, 18);
		immutable ulong B15 = rotate_left(A[ 4] ^ D0, 27);
		immutable ulong B16 = rotate_left(A[ 5] ^ D1, 36);
		immutable ulong B17 = rotate_left(A[11] ^ D2, 10);
		immutable ulong B18 = rotate_left(A[17] ^ D3, 15);
		immutable ulong B19 = rotate_left(A[23] ^ D4, 56);
		immutable ulong B20 = rotate_left(A[ 2] ^ D3, 62);
		immutable ulong B21 = rotate_left(A[ 8] ^ D4, 55);
		immutable ulong B22 = rotate_left(A[14] ^ D0, 39);
		immutable ulong B23 = rotate_left(A[15] ^ D1, 41);
		immutable ulong B24 = rotate_left(A[21] ^ D2, 2);

		A[ 0] = B00 ^ (~B01 & B02);
		A[ 1] = B01 ^ (~B02 & B03);
		A[ 2] = B02 ^ (~B03 & B04);
		A[ 3] = B03 ^ (~B04 & B00);
		A[ 4] = B04 ^ (~B00 & B01);
		A[ 5] = B05 ^ (~B06 & B07);
		A[ 6] = B06 ^ (~B07 & B08);
		A[ 7] = B07 ^ (~B08 & B09);
		A[ 8] = B08 ^ (~B09 & B05);
		A[ 9] = B09 ^ (~B05 & B06);
		A[10] = B10 ^ (~B11 & B12);
		A[11] = B11 ^ (~B12 & B13);
		A[12] = B12 ^ (~B13 & B14);
		A[13] = B13 ^ (~B14 & B10);
		A[14] = B14 ^ (~B10 & B11);
		A[15] = B15 ^ (~B16 & B17);
		A[16] = B16 ^ (~B17 & B18);
		A[17] = B17 ^ (~B18 & B19);
		A[18] = B18 ^ (~B19 & B15);
		A[19] = B19 ^ (~B15 & B16);
		A[20] = B20 ^ (~B21 & B22);
		A[21] = B21 ^ (~B22 & B23);
		A[22] = B22 ^ (~B23 & B24);
		A[23] = B23 ^ (~B24 & B20);
		A[24] = B24 ^ (~B20 & B21);

		A[0] ^= RC[i];
	}
}

}

Keccak_1600::Keccak_1600(size_t output_bits) :
	output_bits(output_bits),
	bitrate(1600 - 2*output_bits),
	S(25),
	S_pos(0)
{
	// We only support the parameters for the SHA-3 proposal

	if (output_bits != 224 && output_bits != 256 &&
		output_bits != 384 && output_bits != 512)
		throw new Invalid_Argument("Keccak_1600: Invalid output length " +
									  std::to_string(output_bits));
}

string Keccak_1600::name() const
{
	return "Keccak-1600(" + std::to_string(output_bits) + ")";
}

HashFunction* Keccak_1600::clone() const
{
	return new Keccak_1600(output_bits);
}

void Keccak_1600::clear()
{
	zeroise(S);
	S_pos = 0;
}

void Keccak_1600::add_data(in byte* input, size_t length)
{
	if (length == 0)
		return;

	while(length)
	{
		size_t to_take = std::min(length, bitrate / 8 - S_pos);

		length -= to_take;

		while(to_take && S_pos % 8)
		{
			S[S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (S_pos % 8));

			++S_pos;
			++input;
			--to_take;
		}

		while(to_take && to_take % 8 == 0)
		{
			S[S_pos / 8] ^= load_le!ulong(input, 0);
			S_pos += 8;
			input += 8;
			to_take -= 8;
		}

		while(to_take)
		{
			S[S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (S_pos % 8));

			++S_pos;
			++input;
			--to_take;
		}

		if (S_pos == bitrate / 8)
		{
			keccak_f_1600(&S[0]);
			S_pos = 0;
		}
	}
}

void Keccak_1600::final_result(byte* output)
{
	Vector!( byte ) padding(bitrate / 8 - S_pos);

	padding[0] = 0x01;
	padding[padding.size()-1] |= 0x80;

	add_data(&padding[0], padding.size());

	/*
	* We never have to run the permutation again because we only support
	* limited output lengths
	*/
	for (size_t i = 0; i != output_bits/8; ++i)
		output[i] = get_byte(7 - (i % 8), S[i/8]);

	clear();
}

}
