/*
* XOR operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.xor_buf;

import botan.utils.types;
import botan.utils.types;
/**
* XOR arrays. Postcondition output[i] = input[i] ^ output[i] forall i = 0...length
* @param output the input/output buffer
* @param input the read-only input buffer
* @param length the length of the buffers
*/
void xor_buf(T)(T* output, in T* input, size_t length)
{
	while(length >= 8)
	{
		output[0] ^= input[0]; output[1] ^= input[1];
		output[2] ^= input[2]; output[3] ^= input[3];
		output[4] ^= input[4]; output[5] ^= input[5];
		output[6] ^= input[6]; output[7] ^= input[7];

		output += 8; input += 8; length -= 8;
	}

	for (size_t i = 0; i != length; ++i)
		output[i] ^= input[i];
}

/**
* XOR arrays. Postcondition output[i] = input[i] ^ in2[i] forall i = 0...length
* @param output the output buffer
* @param input the first input buffer
* @param in2 the second output buffer
* @param length the length of the three buffers
*/
void xor_buf(T)(T* output,
				 in T* input,
				 in T* input2,
				 size_t length)
{
	while(length >= 8)
	{
		output[0] = input[0] ^ in2[0];
		output[1] = input[1] ^ in2[1];
		output[2] = input[2] ^ in2[2];
		output[3] = input[3] ^ in2[3];
		output[4] = input[4] ^ in2[4];
		output[5] = input[5] ^ in2[5];
		output[6] = input[6] ^ in2[6];
		output[7] = input[7] ^ in2[7];

		input += 8; input2 += 8; output += 8; length -= 8;
	}

	for (size_t i = 0; i != length; ++i)
		output[i] = input[i] ^ input2[i];
}

static if (BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK) {

	void xor_buf(ubyte* output, in ubyte* input, size_t length)
	{
		while(length >= 8)
		{
			*cast(ulong*)(output) ^= *cast(const ulong*)(input);
			output += 8; input += 8; length -= 8;
		}

		for (size_t i = 0; i != length; ++i)
			output[i] ^= input[i];
	}

	void xor_buf(ubyte* output,
				  in ubyte* input,
				  in ubyte* input2,
				  size_t length)
	{
		while(length >= 8)
		{
			*cast(ulong*)(output) =
				*cast(const ulong*)(input) ^
				*cast(const ulong*)(input2);

			input += 8; input2 += 8; output += 8; length -= 8;
		}

		for (size_t i = 0; i != length; ++i)
			output[i] = input[i] ^ input2[i];
	}

}

void xor_buf(Alloc, Alloc2)(Vector!( ubyte, Alloc ) output,
			 in Vector!( ubyte, Alloc2 ) input,
			 size_t n)
{
	xor_buf(&output[0], &input[0], n);
}

void xor_buf(Alloc)(ref Vector!( ubyte, Alloc ) output,
				 in ubyte* input,
				 size_t n)
{
	xor_buf(&output[0], input, n);
}

void xor_buf(Alloc, Alloc2)(Vector!( ubyte, Alloc ) output,
							 in ubyte* input,
							 ref in Vector!( ubyte, Alloc2 ) input2,
							 size_t n)
{
	xor_buf(&output[0], &input[0], &input2[0], n);
}

// fixme: Move into Vector type
Vector!(T, Alloc)
	opOpAssign(string op, T, Alloc, Alloc2)(Vector!(T, Alloc) output,
			 					 in Vector!( T, Alloc2 ) input)
		if (op == "^=")
{
	if (output.length < input.length)
		output.resize(input.length);

	xor_buf(&output[0], &input[0], input.length);
	return output;
}