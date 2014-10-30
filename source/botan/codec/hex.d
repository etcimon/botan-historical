/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.codec.hex;

import botan.alloc.zeroize;
import botan.codec.hex;
import botan.utils.mem_ops;
import std.exception;
import string;

/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void hex_encode(char* output,
                in ubyte* input,
                size_t input_length,
                bool uppercase = true)
{
	immutable ubyte[16] BIN_TO_HEX_UPPER = [
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'A', 'B', 'C', 'D', 'E', 'F' ];
	
	immutable ubyte[16] BIN_TO_HEX_LOWER = [
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' ];
	
	const ubyte* tbl = uppercase ? BIN_TO_HEX_UPPER : BIN_TO_HEX_LOWER;
	
	for (size_t i = 0; i != input_length; ++i)
	{
		ubyte x = input[i];
		output[2*i  ] = tbl[(x >> 4) & 0x0F];
		output[2*i+1] = tbl[(x	  ) & 0x0F];
	}
}

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
string hex_encode(in ubyte* input,
                  size_t input_length,
                  bool uppercase = true)
{
	string output;
	output.capacity = 2 * input_length;
	
	if (input_length)
		hex_encode(&output[0], input, input_length, uppercase);
	
	return output;
}

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
string hex_encode(Alloc)(in Vector!( ubyte, Alloc ) input,
							bool uppercase = true)
{
	return hex_encode(&input[0], input.length, uppercase);
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*		  bytes of input were actually consumed. If less than
*		  input_length, then the range input[consumed:length]
*		  should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(ubyte* output,
                  string input,
                  size_t input_length,
                  ref size_t input_consumed,
                  bool ignore_ws = true)
{
	/*
	* Mapping of hex characters to either their binary equivalent
	* or to an error code.
	*  If valid hex (0-9 A-F a-f), the value.
	*  If whitespace, then 0x80
	*  Otherwise 0xFF
	* Warning: this table assumes ASCII character encodings
	*/
	
	immutable ubyte[256] HEX_TO_BIN = [
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
		0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
		0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ];
	
	ubyte* out_ptr = output;
	bool top_nibble = true;
	
	clear_mem(output, input_length / 2);
	
	for (size_t i = 0; i != input_length; ++i)
	{
		const ubyte bin = HEX_TO_BIN[cast(ubyte)(input[i])];
		
		if (bin >= 0x10)
		{
			if (bin == 0x80 && ignore_ws)
				continue;
			
			string bad_char = input[i];
			if (bad_char == "\t")
				bad_char = "\\t";
			else if (bad_char == "\n")
				bad_char = "\\n";
			
			throw new Invalid_Argument("hex_decode: invalid hex character '" ~ bad_char ~ "'");
		}
		
		*out_ptr |= bin << (top_nibble*4);
		
		top_nibble = !top_nibble;
		if (top_nibble)
			++out_ptr;
	}
	
	input_consumed = input_length;
	size_t written = (out_ptr - output);
	
	/*
	* We only got half of a ubyte at the end; zap the half-written
	* output and mark it as unread
	*/
	if (!top_nibble)
	{
		*out_ptr = 0;
		input_consumed -= 1;
	}
	
	return written;
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(ubyte* output,
                  string input,
                  size_t input_length,
                  bool ignore_ws = true)
{
	size_t consumed = 0;
	size_t written = hex_decode(output, input, input_length,
	                            consumed, ignore_ws);
	
	if (consumed != input_length)
		throw new Invalid_Argument("hex_decode: input did not have full bytes");
	
	return written;
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(ubyte* output,
                  in string input,
                  bool ignore_ws = true)
{
	return hex_decode(output, &input[0], input.length(), ignore_ws);
}

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Vector!ubyte hex_decode(string input,
                        size_t input_length,
                        bool ignore_ws = true)
{
	Vector!ubyte bin;
	bin.reserve(1 + input_length / 2);
	
	size_t written = hex_decode(&binput[0],
								input,
								input_length,
								ignore_ws);
	
	bin.resize(written);
	return bin;
}

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Vector!ubyte hex_decode(in string input,
                        bool ignore_ws = true)
{
	return hex_decode(&input[0], input.length, ignore_ws);
}

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Secure_Vector!ubyte hex_decode_locked(string input,
                                   size_t input_length,
                                   bool ignore_ws = true)
{
	Secure_Vector!ubyte bin;
	bin.reserve(1 + input_length / 2);
	
	size_t written = hex_decode(&binput[0],
								input,
								input_length,
								ignore_ws = true);
	
	bin.resize(written);
	return bin;
}

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Secure_Vector!ubyte hex_decode_locked(in string input,
                                   bool ignore_ws = true)
{
	return hex_decode_locked(&input[0], input.length, ignore_ws);
}
