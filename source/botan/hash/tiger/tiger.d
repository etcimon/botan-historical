/*
* Tiger
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.tiger;
import botan.exceptn;
import botan.loadstor;
import botan.parsing;
namespace {

/*
* Tiger Mixing Function
*/
 void mix(secure_vector!ulong& X)
{
	X[0] -= X[7] ^ 0xA5A5A5A5A5A5A5A5;
	X[1] ^= X[0];
	X[2] += X[1];
	X[3] -= X[2] ^ ((~X[1]) << 19);
	X[4] ^= X[3];
	X[5] += X[4];
	X[6] -= X[5] ^ ((~X[4]) >> 23);
	X[7] ^= X[6];

	X[0] += X[7];
	X[1] -= X[0] ^ ((~X[7]) << 19);
	X[2] ^= X[1];
	X[3] += X[2];
	X[4] -= X[3] ^ ((~X[2]) >> 23);
	X[5] ^= X[4];
	X[6] += X[5];
	X[7] -= X[6] ^ 0x0123456789ABCDEF;
}

}

/*
* Tiger Compression Function
*/
void Tiger::compress_n(in byte* input, size_t blocks)
{
	ulong A = digest[0], B = digest[1], C = digest[2];

	for (size_t i = 0; i != blocks; ++i)
	{
		load_le(&X[0], input, X.size());

		pass(A, B, C, X, 5); mix(X);
		pass(C, A, B, X, 7); mix(X);
		pass(B, C, A, X, 9);

		for (size_t j = 3; j != passes; ++j)
		{
			mix(X);
			pass(A, B, C, X, 9);
			ulong T = A; A = C; C = B; B = T;
		}

		A = (digest[0] ^= A);
		B = digest[1] = B - digest[1];
		C = (digest[2] += C);

		input += hash_block_size();
	}
}

/*
* Copy out the digest
*/
void Tiger::copy_out(byte* output)
{
	for (size_t i = 0; i != output_length(); ++i)
		output[i] = get_byte(7 - (i % 8), digest[i/8]);
}

/*
* Tiger Pass
*/
void Tiger::pass(ref ulong A, ref ulong B, ref ulong C,
					  const secure_vector!ulong& X,
					  byte mul)
{
	C ^= X[0];
	A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
		  SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
	B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
		  SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
	B *= mul;

	A ^= X[1];
	B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
		  SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
	C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
		  SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
	C *= mul;

	B ^= X[2];
	C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
		  SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
	A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
		  SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
	A *= mul;

	C ^= X[3];
	A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
		  SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
	B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
		  SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
	B *= mul;

	A ^= X[4];
	B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
		  SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
	C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
		  SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
	C *= mul;

	B ^= X[5];
	C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
		  SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
	A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
		  SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
	A *= mul;

	C ^= X[6];
	A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
		  SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
	B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
		  SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
	B *= mul;

	A ^= X[7];
	B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
		  SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
	C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
		  SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
	C *= mul;
}

/*
* Clear memory of sensitive data
*/
void Tiger::clear()
{
	MDx_HashFunction::clear();
	zeroise(X);
	digest[0] = 0x0123456789ABCDEF;
	digest[1] = 0xFEDCBA9876543210;
	digest[2] = 0xF096A5B4C3B2E187;
}

/*
* Return the name of this type
*/
string Tiger::name() const
{
	return "Tiger(" ~ std.conv.to!string(output_length()) ~ "," ~
							std.conv.to!string(passes) ~ ")";
}

/*
* Tiger Constructor
*/
Tiger::Tiger(size_t hash_len, size_t passes) :
	MDx_HashFunction(64, false, false),
	X(8),
	digest(3),
	hash_len(hash_len),
	passes(passes)
{
	if (output_length() != 16 && output_length() != 20 && output_length() != 24)
		throw new Invalid_Argument("Tiger: Illegal hash output size: " ~
									  std.conv.to!string(output_length()));

	if (passes < 3)
		throw new Invalid_Argument("Tiger: Invalid number of passes: "
									  + std.conv.to!string(passes));
	clear();
}

}
