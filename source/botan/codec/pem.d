/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.codec.pem;
import botan.filters.filters;
import botan.utils.parsing;
import botan.filters.data_src;
import botan.utils.types;
import std.array : Appender;

struct PEM
{

    /**
    * Encode some binary data in PEM format
    */
    static string encode(in ubyte* der, size_t length, in string label, size_t width = 64)
    {
        const string PEM_HEADER = "-----BEGIN " ~ label ~ "-----";
        const string PEM_TRAILER = "-----END " ~ label ~ "-----";
        
        Pipe pipe = Pipe(new Base64_Encoder(true, width));
        pipe.process_msg(der, length);
        return (PEM_HEADER + pipe.toString() + PEM_TRAILER);
    }

    /**
    * Encode some binary data in PEM format
    */
    static string encode(in Vector!ubyte data, in string label, size_t line_width = 64)
    {
        return encode(data.ptr, data.length, label, line_width);
    }

    /**
    * Encode some binary data in PEM format
    */
    static string encode(in Secure_Vector!ubyte data, in string label, size_t line_width = 64)
    {
        return encode(data.ptr, data.length, label, line_width);
    }

    /**
    * Decode PEM data
    * @param pem a datasource containing PEM encoded data
    * @param label is set to the PEM label found for later inspection
    */
    /*
    * Decode PEM down to raw BER/DER
    */
    static Secure_Vector!ubyte decode(DataSource source, ref string label)
    {
        Appender!string label_buf;
        __gshared immutable size_t RANDOM_CHAR_LIMIT = 8;
        
        const string PEM_HEADER1 = "-----BEGIN ";
        const string PEM_HEADER2 = "-----";
        size_t position = 0;
        
        while (position != PEM_HEADER1.length)
        {
            ubyte b;
            if (!source.read_byte(b))
                throw new Decoding_Error("PEM: No PEM header found");
            if (b == PEM_HEADER1[position])
                ++position;
            else if (position >= RANDOM_CHAR_LIMIT)
                throw new Decoding_Error("PEM: Malformed PEM header");
            else
                position = 0;
        }
        position = 0;
        while (position != PEM_HEADER2.length)
        {
            ubyte b;
            if (!source.read_byte(b))
                throw new Decoding_Error("PEM: No PEM header found");
            if (b == PEM_HEADER2[position])
                ++position;
            else if (position)
                throw new Decoding_Error("PEM: Malformed PEM header");
            
            if (position == 0)
                label_buf ~= cast(char) b;
        }
        label = label_buf.data;

        Pipe base64 = Pipe(new Base64_Decoder);
        base64.start_msg();
        const string PEM_TRAILER = "-----END " ~ label ~ "-----";
        position = 0;
        while (position != PEM_TRAILER.length)
        {
            ubyte b;
            if (!source.read_byte(b))
                throw new Decoding_Error("PEM: No PEM trailer found");
            if (b == PEM_TRAILER[position])
                ++position;
            else if (position)
                throw new Decoding_Error("PEM: Malformed PEM trailer");
            
            if (position == 0)
                base64.write(b);
        }
        base64.end_msg();
        return base64.read_all();
    }

    /**
    * Decode PEM data
    * @param pem a string containing PEM encoded data
    * @param label is set to the PEM label found for later inspection
    */
    static Secure_Vector!ubyte decode(in string pem, ref string label)
    {
        auto src = scoped!DataSource_Memory(pem);
        return decode(src, label);
    }
    /**
    * Decode PEM data
    * @param pem a datasource containing PEM encoded data
    * @param label is what we expect the label to be
    */
    static Secure_Vector!ubyte decode_check_label(DataSource source, in string label_want)
    {
        string label_got;
        Secure_Vector!ubyte ber = decode(source, label_got);
        if (label_got != label_want)
            throw new Decoding_Error("PEM: Label mismatch, wanted " ~ label_want ~ ", got " ~ label_got);
        return ber;
    }

    /**
    * Decode PEM data
    * @param pem a string containing PEM encoded data
    * @param label is what we expect the label to be
    */
    static Secure_Vector!ubyte decode_check_label(in string pem,
                                        in string label_want)
    {
        auto src = scoped!DataSource_Memory(pem);
        return decode_check_label(src, label_want);
    }

    /**
    * Heuristic test for PEM data.
    * Search for a PEM signature
    */
    static bool matches(DataSource source, in string extra = "", size_t search_range = 4096)
    {
        const string PEM_HEADER = "-----BEGIN " ~ extra;
        
        Secure_Vector!ubyte search_buf = Secure_Vector!ubyte(search_range);
        size_t got = source.peek(search_buf.ptr, search_buf.length, 0);
        
        if (got < PEM_HEADER.length)
            return false;
        
        size_t index = 0;
        
        foreach (size_t j; 0 .. got)
        {
            if (search_buf[j] == PEM_HEADER[index])
                ++index;
            else
                index = 0;
            if (index == PEM_HEADER.length)
                return true;
        }
        return false;
    }

}