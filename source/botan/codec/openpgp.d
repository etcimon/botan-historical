/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.codec.openpgp;

import botan.filters.filters;
import botan.filters.basefilt;
import botan.utils.charset;
import botan.checksum.crc24;
import botan.filters.data_src;
import std.array : Appender;
import botan.utils.containers.hashmap;
import botan.utils.types;

/**
* @param input the input data
* @param length length of input in bytes
* @param label the human-readable label
* @param headers a set of key/value pairs included in the header
*/
string PGP_encode(in ubyte* input, size_t length, in string label,
                  in HashMap!(string, string) headers)
{
	const string PGP_HEADER = "-----BEGIN PGP " ~ label ~ "-----";
	const string PGP_TRAILER = "-----END PGP " ~ label ~ "-----";
	__gshared immutable size_t PGP_WIDTH = 64;
	
	Appender!string pgp_encoded = PGP_HEADER;
	
	if (headers.get("Version") != null)
		pgp_encoded ~= "Version: " ~ headers["Version"] ~ '\n';
	

	foreach(k, v; headers)
	{
		if (k != "Version")
			pgp_encoded ~= k ~ ": " ~ v ~ '\n';
	}
	pgp_encoded ~= '\n';
	
	Pipe pipe = Pipe(new Fork(
		new Base64_Encoder(true, PGP_WIDTH),
		new Chain(new Hash_Filter(new CRC24), new Base64_Encoder)
		)
	);
	
	pipe.process_msg(input, length);
	
	pgp_encoded ~= pipe.toString(0);
	pgp_encoded ~= '=' ~ pipe.toString(1) ~ '\n';
	pgp_encoded ~= PGP_TRAILER;
	
	return pgp_encoded.data;
}

/**
* @param input the input data
* @param length length of input in bytes
* @param type the human-readable label
*/
string PGP_encode(in ubyte* input, size_t length, in string type)
{
	HashMap!(string, string) empty;
	return PGP_encode(input, length, type, empty);
}

/**
* @param source the input source
* @param label is set to the human-readable label
* @param headers is set to any headers
* @return decoded output as raw binary
*/
Secure_Vector!ubyte PGP_decode(DataSource source,
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
		if (!source.read_byte(b))
			throw new Decoding_Error("PGP: No PGP header found");
		if (b == PGP_HEADER1[position])
			++position;
		else if (position >= RANDOM_CHAR_LIMIT)
			throw new Decoding_Error("PGP: Malformed PGP header");
		else
			position = 0;
	}
	position = 0;
	Appender!string label_buf;
	while (position != PGP_HEADER2.length)
	{
		ubyte b;
		if (!source.read_byte(b))
			throw new Decoding_Error("PGP: No PGP header found");
		if (b == PGP_HEADER2[position])
			++position;
		else if (position)
			throw new Decoding_Error("PGP: Malformed PGP header");
		
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
			if (!source.read_byte(b))
				throw new Decoding_Error("PGP: Bad armor header");
			if (b != '\n')
				this_header ~= cast(char)(b);
		}
		
		end_of_headers = true;
		for (size_t j = 0; j != this_header.length; ++j)
			if (!is_space(this_header[j]))
				end_of_headers = false;
		
		if (!end_of_headers)
		{
			import std.algorithm : countUntil;
			ptrdiff_t pos = this_header.countUntil(": ");
			if (pos == -1)
				throw new Decoding_Error("OpenPGP: Bad headers");
			
			string key = this_header[0 .. pos];
			string value = this_header[pos + 2 .. $];
			headers[key] = value;
		}
	}
	
	Pipe base64 = Pipe(new Base64_Decoder,
            			new Fork(	null, 
	         				new Chain(new Hash_Filter(new CRC24),
	          				new Base64_Encoder)
	         			)
	           		);

	base64.start_msg();
	
	const string PGP_TRAILER = "-----END PGP " ~ label ~ "-----";
	position = 0;
	bool newline_seen = 0;
	Appender!string crc;
	while (position != PGP_TRAILER.length)
	{
		ubyte b;
		if (!source.read_byte(b))
			throw new Decoding_Error("PGP: No PGP trailer found");
		if (b == PGP_TRAILER[position])
			++position;
		else if (position)
			throw new Decoding_Error("PGP: Malformed PGP trailer");
		
		if (b == '=' && newline_seen)
		{
			while (b != '\n')
			{
				if (!source.read_byte(b))
					throw new Decoding_Error("PGP: Bad CRC tail");
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
	base64.end_msg();
	
	if (crc.data.length > 0 && crc.data != base64.toString(1))
		throw new Decoding_Error("PGP: Corrupt CRC");
	
	return base64.read_all();
}

/**
* @param source the input source
* @param label is set to the human-readable label
* @return decoded output as raw binary
*/
Secure_Vector!ubyte PGP_decode(DataSource source, ref string label)
{
	HashMap!(string, string) ignored;
	return PGP_decode(source, label, ignored);
}