/*
* XOR operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.xor_buf;

import botan.utils.types;
pure:
/**
* XOR arrays. Postcondition output[i] = input[i] ^ output[i] forall i = 0...length
* @param output the input/output buffer
* @param input the read-only input buffer
* @param length the length of the buffers
*/
void xor_buf(T)(T* output, in T* input, size_t length)
{
	while (length >= 8)
	{
		output[0 .. 8] ^= input[0 .. 8];

		output += 8; input += 8; length -= 8;
	}

	output[0 .. length] ^= input[0 .. length];
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
	while (length >= 8)
	{
		output[0 .. 8] = input[0 .. 8] ^ input2[0 .. 8];

		input += 8; input2 += 8; output += 8; length -= 8;
	}

	output[0 .. length] = input[0 .. length] ^ input2[0 .. length];
}

static if (BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK) {

	void xor_buf(ubyte* output, in ubyte* input, size_t length)
	{
		while (length >= 8)
		{
			*cast(ulong*)(output) ^= *cast(const ulong*)(input);
			output += 8; input += 8; length -= 8;
		}

		output[0 .. length] ^= input[0 .. length];
	}

	void xor_buf(ubyte* output,
				 in ubyte* input,
				 in ubyte* input2,
				 size_t length)
	{
		while (length >= 8)
		{
			*cast(ulong*)(output) = (*cast(const ulong*) input) ^ (*cast(const ulong*)input2);

			input += 8; input2 += 8; output += 8; length -= 8;
		}

		output[0 .. length] = input[0 .. length] ^ input2[0 .. length];
	}

}

void xor_buf(Alloc, Alloc2)(Vector!( ubyte, Alloc ) output,
                            in Vector!( ubyte, Alloc2 ) input,
                            size_t n)
{
	xor_buf(output.ptr, input.ptr, n);
}

void xor_buf(Alloc)(ref Vector!( ubyte, Alloc ) output,
					in ubyte* input,
					size_t n)
{
	xor_buf(output.ptr, input, n);
}

void xor_buf(Alloc, Alloc2)(Vector!( ubyte, Alloc ) output,
							in ubyte* input,
							in Vector!( ubyte, Alloc2 ) input2,
							size_t n)
{
	xor_buf(output.ptr, input.ptr, input2.ptr, n);
}

// fixme: Move into Vector type
Vector!(T, Alloc) opOpAssign(string op, T, Alloc, Alloc2)(Vector!(T, Alloc) output,
                                                          in Vector!( T, Alloc2 ) input)
		if (op == "^=")
{
	if (output.length < input.length)
		output.resize(input.length);

	xor_buf(output.ptr, input.ptr, input.length);
	return output;
}