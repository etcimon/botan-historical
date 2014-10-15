/*
* Base64 Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.b64_filt;

import botan.filters.filter;
import botan.codec.base64;
import botan.charset;
import botan.utils.exceptn;
import std.algorithm;

/**
* This class represents a Base64 encoder.
*/
class Base64_Encoder : Filter
{
public:
	string name() const { return "Base64_Encoder"; }

	/**
	* Input a part of a message to the encoder.
	* @param input the message to input as a ubyte array
	* @param length the length of the ubyte array input
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


	/**
	* Inform the Encoder that the current message shall be closed.
	*/
	void end_msg()
	{
		encode_and_send(&input[0], position, true);
		
		if (trailing_newline || (out_position && line_length))
			send('\n');
		
		out_position = position = 0;
	}

	/**
	* Create a base64 encoder.
	* @param breaks whether to use line breaks in the output
	* @param length the length of the lines of the output
	* @param t_n whether to use a trailing newline
	*/
	this(bool breaks = false, size_t length = 72, bool t_n = false) 
	{
		line_length = breaks ? length : 0;
		trailing_newline = t_n && breaks;
		input = 48;
		output = 64;
		position = 0;
		out_position = 0;
	}

private:
	/*
	* Encode and send a block
	*/
	void encode_and_send(in ubyte* input, size_t length,
	                     bool final_inputs = false)
	{
		while(length)
		{
			const size_t proc = std.algorithm.min(length, input.size());
			
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
	void do_output(in ubyte* input, size_t length)
	{
		if (line_length == 0)
			send(input, length);
		else
		{
			size_t remaining = length, offset = 0;
			while(remaining)
			{
				size_t sent = std.algorithm.min(line_length - out_position, remaining);
				send(input + offset, sent);
				out_position += sent;
				remaining -= sent;
				offset += sent;
				if (out_position == line_length)
				{
					send('\n');
					out_position = 0;
				}
			}
		}
	}


	const size_t line_length;
	const bool trailing_newline;
	Vector!ubyte input, output;
	size_t position, out_position;
};

/**
* This object represents a Base64 decoder.
*/
class Base64_Decoder : Filter
{
public:
	string name() const { return "Base64_Decoder"; }

	/**
	* Input a part of a message to the decoder.
	* @param input the message to input as a ubyte array
	* @param length the length of the ubyte array input
	*/
	void write(in ubyte* input, size_t length)
	{
		while(length)
		{
			size_t to_copy = std.algorithm.min(length, input.size() - position);
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

	/**
	* Finish up the current message
	*/
	void end_msg()
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
			throw new Invalid_Argument("Base64_Decoder: Input not full bytes");
	}

	/**
	* Create a base64 decoder.
	* @param checking the type of checking that shall be performed by
	* the decoder
	*/
	this(Decoder_Checking c = NONE)
	{
		checking = c;
		input = 64;
		output = 48;
		position = 0;
	}

private:
	const Decoder_Checking checking;
	Vector!ubyte input, output;
	size_t position;
};