/*
* Hex Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.hex_filt;

import botan.filters.filter;
import botan.codec.hex;
import botan.utils.parsing;
import botan.utils.charset;
import botan.utils.exceptn;
import botan.utils.types;
import std.algorithm;

/**
* Converts arbitrary binary data to hex strings, optionally with
* newlines inserted
*/
final class Hex_Encoder : Filter
{
public:
	/**
	* Whether to use uppercase or lowercase letters for the encoded string.
	*/
	typedef bool Case;
	enum : Case { Uppercase, Lowercase }

	@property string name() const { return "Hex_Encoder"; }

	/*
	* Convert some data into hex format
	*/
	void write(in ubyte* input, size_t length)
	{
		buffer_insert(m_input, m_position, input, length);
		if (m_position + length >= m_input.length)
		{
			encode_and_send(m_input.ptr, m_input.length);
			input += (m_input.length - m_position);
			length -= (m_input.length - m_position);
			while (length >= m_input.length)
			{
				encode_and_send(input, m_input.length);
				input += m_input.length;
				length -= m_input.length;
			}
			copy_mem(m_input.ptr, input, length);
			m_position = 0;
		}
		m_position += length;
	}

	/*
	* Flush buffers
	*/
	void end_msg()
	{
		encode_and_send(m_input.ptr, m_position);
		if (m_counter && m_line_length)
			send('\n');
		m_counter = m_position = 0;
	}


	/**
	* Create a hex encoder.
	* @param the_case the case to use in the encoded strings.
	*/
	this(Case the_case)
	{ 
		m_casing = the_case;
		m_line_length = 0;
		m_input.resize(HEX_CODEC_BUFFER_SIZE);
		m_output.resize(2*m_input.length);
		m_counter = m_position = 0;
	}


	/**
	* Create a hex encoder.
	* @param newlines should newlines be used
	* @param line_length if newlines are used, how long are lines
	* @param the_case the case to use in the encoded strings
	*/
	this(bool newlines = false, size_t m_line_length = 72, Case the_case = Uppercase)
	{
		m_casing = the_case;
		m_line_length = newlines ? length : 0;
		m_input.resize(HEX_CODEC_BUFFER_SIZE);
		m_output.resize(2*m_input.length);
		m_counter = m_position = 0;
	}
private:
	/*
	* Encode and send a block
	*/
	void encode_and_send(in ubyte* block, size_t length)
	{
		hex_encode(cast(char*)(m_output.ptr), block, length, m_casing == Uppercase);
		
		if (m_line_length == 0)
			send(m_output, 2*length);
		else
		{
			size_t remaining = 2*length, offset = 0;
			while (remaining)
			{
				size_t sent = std.algorithm.min(m_line_length - counter, remaining);
				send(&m_output[offset], sent);
				counter += sent;
				remaining -= sent;
				offset += sent;
				if (counter == m_line_length)
				{
					send('\n');
					counter = 0;
				}
			}
		}
	}


	const Case m_casing;
	const size_t m_line_length;
	Vector!ubyte m_input, m_output;
	size_t m_position, m_counter;
}

/**
* Converts hex strings to bytes
*/
final class Hex_Decoder : Filter
{
public:
	@property string name() const { return "Hex_Decoder"; }

	/*
	* Convert some data from hex format
	*/
	void write(in ubyte* input, size_t length)
	{
		while (length)
		{
			size_t to_copy = std.algorithm.min(length, m_input.length - m_position);
			copy_mem(&m_input[m_position], input, to_copy);
			m_position += to_copy;
			
			size_t consumed = 0;
			size_t written = hex_decode(m_output.ptr,
			                            cast(const(char)*)(m_input.ptr),
			                            m_position,
			                            consumed,
			                            m_checking != FULL_CHECK);
			
			send(m_output, written);
			
			if (consumed != m_position)
			{
				copy_mem(m_input.ptr, &m_input[consumed], m_position - consumed);
				m_position = m_position - consumed;
			}
			else
				m_position = 0;
			
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
		size_t written = hex_decode(m_output.ptr,
		                            cast(const(char)*)(m_input.ptr),
									m_position,
									consumed,
									m_checking != FULL_CHECK);
									
		send(m_output, written);
		
		const bool not_full_bytes = consumed != m_position;
		
		m_position = 0;
		
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
		m_checking = c;
		m_input.resize(HEX_CODEC_BUFFER_SIZE);
		m_output.resize(m_input.length / 2);
		m_position = 0;
	}
private:
	const Decoder_Checking m_checking;
	Vector!ubyte m_input, m_output;
	size_t m_position;
}

/**
* Size used for internal buffer in hex encoder/decoder
*/
immutable size_t HEX_CODEC_BUFFER_SIZE = 256;