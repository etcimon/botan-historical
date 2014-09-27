/*
* Base64 Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/b64_filt.h>
#include <botan/base64.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <algorithm>
/*
* Base64_Encoder Constructor
*/
Base64_Encoder::Base64_Encoder(bool breaks, size_t length, bool t_n) :
	line_length(breaks ? length : 0),
	trailing_newline(t_n && breaks),
	input(48),
	output(64),
	position(0),
	out_position(0)
{
}

/*
* Encode and send a block
*/
void Base64_Encoder::encode_and_send(in byte* input, size_t length,
												 bool final_inputs)
{
	while(length)
	{
		const size_t proc = std::min(length, input.size());

		size_t consumed = 0;
		size_t produced = base64_encode(cast(char*)(&output[0]), input,
												  proc, consumed, final_inputs);

		do_output(&output[0], produced);

		// FIXME: s/proc/consumed/?
		input += proc;
		length -= proc;
	}
}

/*
* Handle the output
*/
void Base64_Encoder::do_output(in byte* input, size_t length)
{
	if (line_length == 0)
		send(input, length);
	else
	{
		size_t remaining = length, offset = 0;
		while(remaining)
		{
			size_t sent = std::min(line_length - out_position, remaining);
			send(input + offset, sent);
			out_position += sent;
			remaining -= sent;
			offset += sent;
			if (out_position == line_length)
			{
				send('');
				out_position = 0;
			}
		}
	}
}

/*
* Convert some data into Base64
*/
void Base64_Encoder::write(in byte* input, size_t length)
{
	buffer_insert(input, position, input, length);
	if (position + length >= input.size())
	{
		encode_and_send(&input[0], input.size());
		input += (input.size() - position);
		length -= (input.size() - position);
		while(length >= input.size())
		{
			encode_and_send(input, input.size());
			input += input.size();
			length -= input.size();
		}
		copy_mem(&input[0], input, length);
		position = 0;
	}
	position += length;
}

/*
* Flush buffers
*/
void Base64_Encoder::end_msg()
{
	encode_and_send(&input[0], position, true);

	if (trailing_newline || (out_position && line_length))
		send('');

	out_position = position = 0;
}

/*
* Base64_Decoder Constructor
*/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) :
	checking(c), input(64), output(48), position(0)
{
}

/*
* Convert some data from Base64
*/
void Base64_Decoder::write(in byte* input, size_t length)
{
	while(length)
	{
		size_t to_copy = std::min<size_t>(length, input.size() - position);
		copy_mem(&input[position], input, to_copy);
		position += to_copy;

		size_t consumed = 0;
		size_t written = base64_decode(&output[0],
												 cast(string)(input[0]),
												 position,
												 consumed,
												 false,
												 checking != FULL_CHECK);

		send(output, written);

		if (consumed != position)
		{
			copy_mem(&input[0], &input[consumed], position - consumed);
			position = position - consumed;
		}
		else
			position = 0;

		length -= to_copy;
		input += to_copy;
	}
}

/*
* Flush buffers
*/
void Base64_Decoder::end_msg()
{
	size_t consumed = 0;
	size_t written = base64_decode(&output[0],
											 cast(string)(input[0]),
											 position,
											 consumed,
											 true,
											 checking != FULL_CHECK);

	send(output, written);

	const bool not_full_bytes = consumed != position;

	position = 0;

	if (not_full_bytes)
		throw new std::invalid_argument("Base64_Decoder: Input not full bytes");
}

}
