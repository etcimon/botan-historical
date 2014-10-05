/*
* Hex Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.hex_filt;
import botan.hex;
import botan.parsing;
import botan.charset;
import botan.exceptn;
import algorithm;
/**
* Size used for internal buffer in hex encoder/decoder
*/
immutable size_t HEX_CODEC_BUFFER_SIZE = 256;

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(bool breaks, size_t length, Case c) :
	casing(c), line_length(breaks ? length : 0)
{
	input.resize(HEX_CODEC_BUFFER_SIZE);
	output.resize(2*input.size());
	counter = position = 0;
}

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(Case c) : casing(c), line_length(0)
{
	input.resize(HEX_CODEC_BUFFER_SIZE);
	output.resize(2*input.size());
	counter = position = 0;
}

/*
* Encode and send a block
*/
void Hex_Encoder::encode_and_send(in ubyte* block, size_t length)
{
	hex_encode(cast(char*)(&output[0]),
				  block, length,
				  casing == Uppercase);

	if (line_length == 0)
		send(output, 2*length);
	else
	{
		size_t remaining = 2*length, offset = 0;
		while(remaining)
		{
			size_t sent = std.algorithm.min(line_length - counter, remaining);
			send(&output[offset], sent);
			counter += sent;
			remaining -= sent;
			offset += sent;
			if (counter == line_length)
			{
				send('');
				counter = 0;
			}
		}
	}
}

/*
* Convert some data into hex format
*/
void Hex_Encoder::write(in ubyte* input, size_t length)
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
void Hex_Encoder::end_msg()
{
	encode_and_send(&input[0], position);
	if (counter && line_length)
		send('');
	counter = position = 0;
}

/*
* Hex_Decoder Constructor
*/
Hex_Decoder::Hex_Decoder(Decoder_Checking c) : checking(c)
{
	input.resize(HEX_CODEC_BUFFER_SIZE);
	output.resize(input.size() / 2);
	position = 0;
}

/*
* Convert some data from hex format
*/
void Hex_Decoder::write(in ubyte* input, size_t length)
{
	while(length)
	{
		size_t to_copy = std.algorithm.min<size_t>(length, input.size() - position);
		copy_mem(&input[position], input, to_copy);
		position += to_copy;

		size_t consumed = 0;
		size_t written = hex_decode(&output[0],
											 cast(string)(input[0]),
											 position,
											 consumed,
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
void Hex_Decoder::end_msg()
{
	size_t consumed = 0;
	size_t written = hex_decode(&output[0],
										 cast(string)(input[0]),
										 position,
										 consumed,
										 checking != FULL_CHECK);

	send(output, written);

	const bool not_full_bytes = consumed != position;

	position = 0;

	if (not_full_bytes)
		throw new std::invalid_argument("Hex_Decoder: Input not full bytes");
}

}
