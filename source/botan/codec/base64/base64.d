/*
* Base64 Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/base64.h>
#include <botan/mem_ops.h>
#include <botan/internal/rounding.h>
#include <stdexcept>
namespace {

static const byte BIN_TO_BASE64[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void do_base64_encode(char out[4], const byte in[3])
{
	out[0] = BIN_TO_BASE64[((in[0] & 0xFC) >> 2)];
	out[1] = BIN_TO_BASE64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	out[2] = BIN_TO_BASE64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
	out[3] = BIN_TO_BASE64[((in[2] & 0x3F)	  )];
}

}

size_t base64_encode(char out[],
							in byte[] in,
							size_t input_length,
							size_t& input_consumed,
							bool final_inputs)
{
	input_consumed = 0;

	size_t input_remaining = input_length;
	size_t output_produced = 0;

	while(input_remaining >= 3)
	{
		do_base64_encode(out + output_produced, in + input_consumed);

		input_consumed += 3;
		output_produced += 4;
		input_remaining -= 3;
	}

	if(final_inputs && input_remaining)
	{
		byte remainder[3] = { 0 };
		for(size_t i = 0; i != input_remaining; ++i)
			remainder[i] = in[input_consumed + i];

		do_base64_encode(out + output_produced, remainder);

		size_t empty_bits = 8 * (3 - input_remaining);
		size_t index = output_produced + 4 - 1;
		while(empty_bits >= 8)
		{
			out[index--] = '=';
			empty_bits -= 6;
		}

		input_consumed += input_remaining;
		output_produced += 4;
	}

	return output_produced;
}

string base64_encode(in byte[] input,
								  size_t input_length)
{
	string output((round_up<size_t>(input_length, 3) / 3) * 4, 0);

	size_t consumed = 0;
	size_t produced = base64_encode(&output[0],
											  input, input_length,
											  consumed, true);

	BOTAN_ASSERT_EQUAL(consumed, input_length, "Consumed the entire input");
	BOTAN_ASSERT_EQUAL(produced, output.size(), "Produced expected size");

	return output;
}

size_t base64_decode(byte output[],
							const char input[],
							size_t input_length,
							size_t& input_consumed,
							bool final_inputs,
							bool ignore_ws)
{
	/*
	* Base64 Decoder Lookup Table
	* Warning: assumes ASCII encodings
	*/
	static const byte BASE64_TO_BIN[256] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
		0x80, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35,
		0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
		0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
		0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
		0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
		0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
		0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
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
	byte decode_buf[4];
	size_t decode_buf_pos = 0;
	size_t final_truncate = 0;

	clear_mem(output, input_length * 3 / 4);

	for(size_t i = 0; i != input_length; ++i)
	{
		const byte bin = BASE64_TO_BIN[cast(byte)(input[i])];

		if(bin <= 0x3F)
		{
			decode_buf[decode_buf_pos] = bin;
			decode_buf_pos += 1;
		}
		else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
		{
			string bad_char(1, input[i]);
			if(bad_char == "\t")
			  bad_char = "\\t";
			else if(bad_char == "")
			  bad_char = "\";
			else if(bad_char == "\r")
			  bad_char = "\\r";

			throw std::invalid_argument(
			  string("base64_decode: invalid base64 character '") +
			  bad_char + "'");
		}

		/*
		* If we're at the end of the input, pad with 0s and truncate
		*/
		if(final_inputs && (i == input_length - 1))
		{
			if(decode_buf_pos)
			{
				for(size_t i = decode_buf_pos; i != 4; ++i)
					decode_buf[i] = 0;
				final_truncate = (4 - decode_buf_pos);
				decode_buf_pos = 4;
			}
		}

		if(decode_buf_pos == 4)
		{
			out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
			out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
			out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];

			out_ptr += 3;
			decode_buf_pos = 0;
			input_consumed = i+1;
		}
	}

	while(input_consumed < input_length &&
			BASE64_TO_BIN[cast(byte)(input[input_consumed])] == 0x80)
	{
		++input_consumed;
	}

	size_t written = (out_ptr - output) - final_truncate;

	return written;
}

size_t base64_decode(byte output[],
							const char input[],
							size_t input_length,
							bool ignore_ws)
{
	size_t consumed = 0;
	size_t written = base64_decode(output, input, input_length,
											 consumed, true, ignore_ws);

	if(consumed != input_length)
		throw std::invalid_argument("base64_decode: input did not have full bytes");

	return written;
}

size_t base64_decode(byte output[],
							in string input,
							bool ignore_ws)
{
	return base64_decode(output, &input[0], input.length(), ignore_ws);
}

SafeArray!byte base64_decode(const char input[],
											size_t input_length,
											bool ignore_ws)
{
	SafeArray!byte bin((round_up<size_t>(input_length, 4) * 3) / 4);

	size_t written = base64_decode(&bin[0],
											 input,
											 input_length,
											 ignore_ws);

	bin.resize(written);
	return bin;
}

SafeArray!byte base64_decode(in string input,
											bool ignore_ws)
{
	return base64_decode(&input[0], input.size(), ignore_ws);
}}
