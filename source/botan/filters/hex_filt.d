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
final class HexEncoder : Filter, Filterable
{
public:
    /**
    * Whether to use uppercase or lowercase letters for the encoded string.
    */
    alias Case = bool;
    enum : Case { Uppercase, Lowercase }

    override @property string name() const { return "HexEncoder"; }

    /*
    * Convert some data into hex format
    */
    override void write(ubyte* input, size_t length)
    {
        bufferInsert(m_input, m_position, input, length);
        if (m_position + length >= m_input.length)
        {
            encodeAndSend(m_input.ptr, m_input.length);
            input += (m_input.length - m_position);
            length -= (m_input.length - m_position);
            while (length >= m_input.length)
            {
                encodeAndSend(input, m_input.length);
                input += m_input.length;
                length -= m_input.length;
            }
            copyMem(m_input.ptr, input, length);
            m_position = 0;
        }
        m_position += length;
    }

    /*
    * Flush buffers
    */
    override void endMsg()
    {
        encodeAndSend(m_input.ptr, m_position);
        if (m_counter && m_line_length)
            send('\n');
        m_counter = m_position = 0;
    }


    /**
    * Create a hex encoder.
    * @param the_case = the case to use in the encoded strings.
    */
    this(Case the_case)
    { 
        m_casing = the_case;
        m_line_length = 0;
        m_input.reserve(HEX_CODEC_BUFFER_SIZE);
        m_output.reserve(2*m_input.length);
        m_counter = m_position = 0;
    }


    /**
    * Create a hex encoder.
    * @param newlines = should newlines be used
    * @param line_length = if newlines are used, how long are lines
    * @param the_case = the case to use in the encoded strings
    */
    this(bool newlines = false, size_t m_line_length = 72, Case the_case = Uppercase)
    {
        m_casing = the_case;
        m_line_length = newlines ? length : 0;
        m_input.reserve(HEX_CODEC_BUFFER_SIZE);
        m_output.reserve(2*m_input.length);
        m_counter = m_position = 0;
    }
private:
    /*
    * Encode and send a block
    */
    void encodeAndSend(in ubyte* block, size_t length)
    {
        hexEncode(cast(char*)(m_output.ptr), block, length, m_casing == Uppercase);
        
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
final class HexDecoder : Filter, Filterable
{
public:
    override @property string name() const { return "HexDecoder"; }

    /*
    * Convert some data from hex format
    */
    override void write(ubyte* input, size_t length)
    {
        while (length)
        {
            size_t to_copy = std.algorithm.min(length, m_input.length - m_position);
            copyMem(&m_input[m_position], input, to_copy);
            m_position += to_copy;
            
            size_t consumed = 0;
            size_t written = hexDecode(m_output.ptr,
                                        cast(const(char)*)(m_input.ptr),
                                        m_position,
                                        consumed,
                                        m_checking != FULL_CHECK);
            
            send(m_output, written);
            
            if (consumed != m_position)
            {
                copyMem(m_input.ptr, &m_input[consumed], m_position - consumed);
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
    override void endMsg()
    {
        size_t consumed = 0;
        size_t written = hexDecode(m_output.ptr,
                                    cast(const(char)*)(m_input.ptr),
                                    m_position,
                                    consumed,
                                    m_checking != FULL_CHECK);
                                    
        send(m_output, written);
        
        const bool not_full_bytes = consumed != m_position;
        
        m_position = 0;
        
        if (not_full_bytes)
            throw new InvalidArgument("HexDecoder: Input not full bytes");
    }


    /**
    * Construct a Hex Decoder using the specified
    * character checking.
    * @param checking = the checking to use during decoding.
    */
    this(DecoderChecking c = NONE)
    {
        m_checking = c;
        m_input.reserve(HEX_CODEC_BUFFER_SIZE);
        m_output.reserve(m_input.length / 2);
        m_position = 0;
    }
private:
    const DecoderChecking m_checking;
    Vector!ubyte m_input, m_output;
    size_t m_position;
}

/**
* Size used for internal buffer in hex encoder/decoder
*/
immutable size_t HEX_CODEC_BUFFER_SIZE = 256;