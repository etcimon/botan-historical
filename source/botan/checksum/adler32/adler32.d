/*
* Adler32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.adler32;
import botan.loadstor;
namespace {

void adler32_update(in byte* input, size_t length,
						  ushort& S1, ushort& S2)
{
	uint S1x = S1;
	uint S2x = S2;

	while(length >= 16)
	{
		S1x += input[ 0]; S2x += S1x;
		S1x += input[ 1]; S2x += S1x;
		S1x += input[ 2]; S2x += S1x;
		S1x += input[ 3]; S2x += S1x;
		S1x += input[ 4]; S2x += S1x;
		S1x += input[ 5]; S2x += S1x;
		S1x += input[ 6]; S2x += S1x;
		S1x += input[ 7]; S2x += S1x;
		S1x += input[ 8]; S2x += S1x;
		S1x += input[ 9]; S2x += S1x;
		S1x += input[10]; S2x += S1x;
		S1x += input[11]; S2x += S1x;
		S1x += input[12]; S2x += S1x;
		S1x += input[13]; S2x += S1x;
		S1x += input[14]; S2x += S1x;
		S1x += input[15]; S2x += S1x;
		input += 16;
		length -= 16;
	}

	for (size_t j = 0; j != length; ++j)
	{
		S1x += input[j];
		S2x += S1x;
	}

	S1 = S1x % 65521;
	S2 = S2x % 65521;
}

}

/*
* Update an Adler32 Checksum
*/
void Adler32::add_data(in byte* input, size_t length)
{
	const size_t PROCESS_AMOUNT = 5552;

	while(length >= PROCESS_AMOUNT)
	{
		adler32_update(input, PROCESS_AMOUNT, S1, S2);
		input += PROCESS_AMOUNT;
		length -= PROCESS_AMOUNT;
	}

	adler32_update(input, length, S1, S2);
}

/*
* Finalize an Adler32 Checksum
*/
void Adler32::final_result(byte* output)
{
	store_be(output, S2, S1);
	clear();
}

}
