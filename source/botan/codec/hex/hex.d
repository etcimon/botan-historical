/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <stdexcept>
void hex_encode(char output[],
					 const byte input[],
					 size_t input_length,
					 bool uppercase)
{
	static const byte BIN_TO_HEX_UPPER[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'A', 'B', 'C', 'D', 'E', 'F' };

	static const byte BIN_TO_HEX_LOWER[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };

	const byte* tbl = uppercase ? BIN_TO_HEX_UPPER : BIN_TO_HEX_LOWER;

	for(size_t i = 0; i != input_length; ++i)
	{
		byte x = input[i];
		output[2*i  ] = tbl[(x >> 4) & 0x0F];
		output[2*i+1] = tbl[(x	  ) & 0x0F];
	}
}

string hex_encode(const byte input[],
							  size_t input_length,
							  bool uppercase)
{
	string output(2 * input_length, 0);

	if(input_length)
		hex_encode(&output[0], input, input_length, uppercase);

	return output;
}

size_t hex_decode(byte output[],
						const char input[],
						size_t input_length,
						size_t& input_consumed,
						bool ignore_ws)
{
	/*
	* Mapping of hex characters to either their binary equivalent
	* or to an error code.
	*  If valid hex (0-9 A-F a-f), the value.
	*  If whitespace, then 0x80
	*  Otherwise 0xFF
	* Warning: this table assumes ASCII character encodings
	*/

	static const byte HEX_TO_BIN[256] = {
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
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	byte* out_ptr = output;
	bool top_nibble = true;

	clear_mem(output, input_length / 2);

	for(size_t i = 0; i != input_length; ++i)
	{
		const byte bin = HEX_TO_BIN[static_cast<byte>(input[i])];

		if(bin >= 0x10)
		{
			if(bin == 0x80 && ignore_ws)
				continue;

			string bad_char(1, input[i]);
			if(bad_char == "\t")
			  bad_char = "\\t";
			else if(bad_char == "")
			  bad_char = "\";

			throw std::invalid_argument(
			  string("hex_decode: invalid hex character '") +
			  bad_char + "'");
		}

		*out_ptr |= bin << (top_nibble*4);

		top_nibble = !top_nibble;
		if(top_nibble)
			++out_ptr;
	}

	input_consumed = input_length;
	size_t written = (out_ptr - output);

	/*
	* We only got half of a byte at the end; zap the half-written
	* output and mark it as unread
	*/
	if(!top_nibble)
	{
		*out_ptr = 0;
		input_consumed -= 1;
	}

	return written;
}

size_t hex_decode(byte output[],
						const char input[],
						size_t input_length,
						bool ignore_ws)
{
	size_t consumed = 0;
	size_t written = hex_decode(output, input, input_length,
										 consumed, ignore_ws);

	if(consumed != input_length)
		throw std::invalid_argument("hex_decode: input did not have full bytes");

	return written;
}

size_t hex_decode(byte output[],
						in string input,
						bool ignore_ws)
{
	return hex_decode(output, &input[0], input.length(), ignore_ws);
}

SafeArray!byte hex_decode_locked(const char input[],
												  size_t input_length,
												  bool ignore_ws)
{
	SafeArray!byte bin(1 + input_length / 2);

	size_t written = hex_decode(&bin[0],
										 input,
										 input_length,
										 ignore_ws);

	bin.resize(written);
	return bin;
}

SafeArray!byte hex_decode_locked(in string input,
												  bool ignore_ws)
{
	return hex_decode_locked(&input[0], input.size(), ignore_ws);
}

std::vector<byte> hex_decode(const char input[],
									  size_t input_length,
									  bool ignore_ws)
{
	std::vector<byte> bin(1 + input_length / 2);

	size_t written = hex_decode(&bin[0],
										 input,
										 input_length,
										 ignore_ws);

	bin.resize(written);
	return bin;
}

std::vector<byte> hex_decode(in string input,
									  bool ignore_ws)
{
	return hex_decode(&input[0], input.size(), ignore_ws);
}

}
