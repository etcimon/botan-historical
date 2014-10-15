/*
* Hex Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.hex_filt;

import botan.filter;
import botan.codec.hex;
import botan.parsing;
import botan.charset;
import botan.utils.exceptn;
import std.algorithm;

/**
* Converts arbitrary binary data to hex strings, optionally with
* newlines inserted
*/
class Hex_Encoder : Filter
{
public:
	/**
	* Whether to use uppercase or lowercase letters for the encoded string.
	*/
	enum Case { Uppercase, Lowercase };

	string name() const { return "Hex_Encoder"; }

	/*
	* Convert some data into hex format
	*/
	void write(in ubyte* input, size_t length)
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
	void end_msg()
	{
		encode_and_send(&input[0], position);
		if (counter && line_length)
			send('\n');
		counter = position = 0;
	}


	/**
	* Create a hex encoder.
	* @param the_case the case to use in the encoded strings.
	*/
	this(Case the_case)
	{ 
		casing = the_case;
		line_length = 0;
		input.resize(HEX_CODEC_BUFFER_SIZE);
		output.resize(2*input.size());
		counter = position = 0;
	}


	/**
	* Create a hex encoder.
	* @param newlines should newlines be used
	* @param line_length if newlines are used, how long are lines
	* @param the_case the case to use in the encoded strings
	*/
	this(bool newlines = false,
	     size_t line_length = 72,
	     Case the_case = Uppercase)
	{
		casing = the_case;
		line_length = newlines ? length : 0;
		input.resize(HEX_CODEC_BUFFER_SIZE);
		output.resize(2*input.size());
		counter = position = 0;
	}
private:
	/*
	* Encode and send a block
	*/
	void encode_and_send(in ubyte* block, size_t length)
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
					send('\n');
					counter = 0;
				}
			}
		}
	}


	const Case casing;
	const size_t line_length;
	Vector!ubyte input, output;
	size_t position, counter;
};

/**
* Converts hex strings to bytes
*/
class Hex_Decoder : Filter
{
public:
	string name() const { return "Hex_Decoder"; }

	/*
	* Convert some data from hex format
	*/
	void write(in ubyte* input, size_t length)
	{
		while(length)
		{
			size_t to_copy = std.algorithm.min(length, input.size() - position);
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
	void end_msg()
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
			throw new Invalid_Argument("Hex_Decoder: Input not full bytes");
	}


	/**
	* Construct a Hex Decoder using the specified
	* character checking.
	* @param checking the checking to use during decoding.
	*/
	this(Decoder_Checking c = NONE)
	{
		checking = c;
		input.resize(HEX_CODEC_BUFFER_SIZE);
		output.resize(input.size() / 2);
		position = 0;
	}
private:
	const Decoder_Checking checking;
	Vector!ubyte input, output;
	size_t position;
};

/**
* Size used for internal buffer in hex encoder/decoder
*/
immutable size_t HEX_CODEC_BUFFER_SIZE = 256;