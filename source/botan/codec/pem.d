/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.codec.pem;
import botan.filters.filters;
import botan.parsing;
import botan.filters.data_src;

/**
* Encode some binary data in PEM format
*/
/*
* PEM encode BER/DER-encoded objects
*/
string encode(in ubyte* der, size_t length, in string label,
              size_t width = 64)
{
	const string PEM_HEADER = "-----BEGIN " ~ label ~ "-----";
	const string PEM_TRAILER = "-----END " ~ label ~ "-----";
	
	Unique!Pipe pipe = Unique!Pipe.create(new Base64_Encoder(true, width));
	pipe.process_msg(der, length);
	return (PEM_HEADER + pipe.read_all_as_string() + PEM_TRAILER);
}

/**
* Encode some binary data in PEM format
*/
 string encode(in Vector!ubyte data,
								  in string label,
								  size_t line_width = 64)
{
	return encode(&data[0], data.size(), label, line_width);
}

/**
* Encode some binary data in PEM format
*/
 string encode(in SafeVector!ubyte data,
								  in string label,
								  size_t line_width = 64)
{
	return encode(&data[0], data.size(), label, line_width);
}

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/
/*
* Decode PEM down to raw BER/DER
*/
SafeVector!ubyte decode(DataSource source, ref string label)
{
	const size_t RANDOM_CHAR_LIMIT = 8;
	
	const string PEM_HEADER1 = "-----BEGIN ";
	const string PEM_HEADER2 = "-----";
	size_t position = 0;
	
	while(position != PEM_HEADER1.length())
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
	while(position != PEM_HEADER2.length())
	{
		ubyte b;
		if (!source.read_byte(b))
			throw new Decoding_Error("PEM: No PEM header found");
		if (b == PEM_HEADER2[position])
			++position;
		else if (position)
			throw new Decoding_Error("PEM: Malformed PEM header");
		
		if (position == 0)
			label += cast(char)(b);
	}
	
	Pipe base64(new Base64_Decoder);
	base64.start_msg();
	
	const string PEM_TRAILER = "-----END " ~ label ~ "-----";
	position = 0;
	while(position != PEM_TRAILER.length())
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
SafeVector!ubyte decode(in string pem, ref string label)
{
	DataSource_Memory src = new DataSource_Memory(pem);
	scope(exit) delete src;
	return decode(src, label);
}
/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is what we expect the label to be
*/
SafeVector!ubyte decode_check_label(DataSource source,
                                    in string label_want)
{
	string label_got;
	SafeVector!ubyte ber = decode(source, label_got);
	if (label_got != label_want)
		throw new Decoding_Error("PEM: Label mismatch, wanted " ~ label_want +
		                         ", got " ~ label_got);
	return ber;
}

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is what we expect the label to be
*/
SafeVector!ubyte decode_check_label(in string pem,
                                    in string label_want)
{
	DataSource_Memory src = new DataSource_Memory(pem);
	scope(exit) delete src;
	return decode_check_label(src, label_want);
}

/**
* Heuristic test for PEM data.
* Search for a PEM signature
*/
bool matches(DataSource source, in string extra = "",
             size_t search_range = 4096)
{
	const string PEM_HEADER = "-----BEGIN " ~ extra;
	
	SafeVector!ubyte search_buf(search_range);
	size_t got = source.peek(&search_buf[0], search_buf.size(), 0);
	
	if (got < PEM_HEADER.length())
		return false;
	
	size_t index = 0;
	
	for (size_t j = 0; j != got; ++j)
	{
		if (search_buf[j] == PEM_HEADER[index])
			++index;
		else
			index = 0;
		if (index == PEM_HEADER.size())
			return true;
	}
	return false;
}

