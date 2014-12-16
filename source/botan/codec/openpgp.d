/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.codec.openpgp;

import botan.filters.filters;
import botan.filters.basefilt;
import botan.filters.b64_filt;
import botan.utils.charset;
import botan.checksum.crc24;
import botan.filters.data_src;
import std.array : Appender;
import botan.utils.containers.hashmap;
import botan.utils.types;

/**
* @param input = the input data
* @param length = length of input in bytes
* @param label = the human-readable label
* @param headers = a set of key/value pairs included in the header
*/
string PGP_encode(const(ubyte)* input, size_t length, in string label,
                  in HashMap!(string, string) headers)
{
    const string PGP_HEADER = "-----BEGIN PGP " ~ label ~ "-----";
    const string PGP_TRAILER = "-----END PGP " ~ label ~ "-----";
    __gshared immutable size_t PGP_WIDTH = 64;
    
    Appender!string pgp_encoded = PGP_HEADER;
    
    if (headers.get("Version") != null)
        pgp_encoded ~= "Version: " ~ headers["Version"] ~ '\n';

    foreach(const ref string k, const ref string v; headers)
    {
        if (k != "Version")
            pgp_encoded ~= k ~ ": " ~ v ~ '\n';
    }
    pgp_encoded ~= '\n';
    
    Pipe pipe = Pipe(new Fork(
        new Base64Encoder(true, PGP_WIDTH),
        new Chain(new HashFilter(new CRC24), new Base64Encoder)
        )
    );
    
    pipe.processMsg(input, length);
    
    pgp_encoded ~= pipe.toString(0);
    pgp_encoded ~= '=' ~ pipe.toString(1) ~ '\n';
    pgp_encoded ~= PGP_TRAILER;
    
    return pgp_encoded.data;
}

/**
* @param input = the input data
* @param length = length of input in bytes
* @param type = the human-readable label
*/
string PGP_encode(const(ubyte)* input, size_t length, in string type)
{
    HashMap!(string, string) empty;
    return PGP_encode(input, length, type, empty);
}

/**
* @param source = the input source
* @param label = is set to the human-readable label
* @param headers = is set to any headers
* @return decoded output as raw binary
*/
SecureVector!ubyte PGP_decode(DataSource source,
                            ref string label,
                            ref HashMap!(string, string) headers)
{
    __gshared immutable size_t RANDOM_CHAR_LIMIT = 5;
    
    const string PGP_HEADER1 = "-----BEGIN PGP ";
    const string PGP_HEADER2 = "-----";
    size_t position = 0;
    
    while (position != PGP_HEADER1.length)
    {
        ubyte b;
        if (!source.readByte(b))
            throw new DecodingError("PGP: No PGP header found");
        if (b == PGP_HEADER1[position])
            ++position;
        else if (position >= RANDOM_CHAR_LIMIT)
            throw new DecodingError("PGP: Malformed PGP header");
        else
            position = 0;
    }
    position = 0;
    Appender!string label_buf;
    while (position != PGP_HEADER2.length)
    {
        ubyte b;
        if (!source.readByte(b))
            throw new DecodingError("PGP: No PGP header found");
        if (b == PGP_HEADER2[position])
            ++position;
        else if (position)
            throw new DecodingError("PGP: Malformed PGP header");
        
        if (position == 0)
            label_buf ~= cast(char)(b);
    }
    label = label_buf.data;
    headers.clear();
    bool end_of_headers = false;
    while (!end_of_headers)
    {
        string this_header;
        ubyte b = 0;
        while (b != '\n')
        {
            if (!source.readByte(b))
                throw new DecodingError("PGP: Bad armor header");
            if (b != '\n')
                this_header ~= cast(char)(b);
        }
        
        end_of_headers = true;
        for (size_t j = 0; j != this_header.length; ++j)
            if (!isSpace(this_header[j]))
                end_of_headers = false;
        
        if (!end_of_headers)
        {
            import std.algorithm : countUntil;
            ptrdiff_t pos = this_header.countUntil(": ");
            if (pos == -1)
                throw new DecodingError("OpenPGP: Bad headers");
            
            string key = this_header[0 .. pos];
            string value = this_header[pos + 2 .. $];
            headers[key] = value;
        }
    }
    
    Pipe base64 = Pipe(new Base64Decoder,
                        new Fork(    null, 
                             new Chain(new HashFilter(new CRC24),
                              new Base64Encoder)
                         )
                       );

    base64.startMsg();
    
    const string PGP_TRAILER = "-----END PGP " ~ label ~ "-----";
    position = 0;
    bool newline_seen = 0;
    Appender!string crc;
    while (position != PGP_TRAILER.length)
    {
        ubyte b;
        if (!source.readByte(b))
            throw new DecodingError("PGP: No PGP trailer found");
        if (b == PGP_TRAILER[position])
            ++position;
        else if (position)
            throw new DecodingError("PGP: Malformed PGP trailer");
        
        if (b == '=' && newline_seen)
        {
            while (b != '\n')
            {
                if (!source.readByte(b))
                    throw new DecodingError("PGP: Bad CRC tail");
                if (b != '\n')
                    crc ~= cast(char)(b);
            }
        }
        else if (b == '\n')
            newline_seen = true;
        else if (position == 0)
        {
            base64.write(b);
            newline_seen = false;
        }
    }
    base64.endMsg();
    
    if (crc.data.length > 0 && crc.data != base64.toString(1))
        throw new DecodingError("PGP: Corrupt CRC");
    
    return base64.readAll();
}

/**
* @param source = the input source
* @param label = is set to the human-readable label
* @return decoded output as raw binary
*/
SecureVector!ubyte PGP_decode(DataSource source, ref string label)
{
    HashMap!(string, string) ignored;
    return PGP_decode(source, label, ignored);
}