/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/openpgp.h>
#include <botan/filters.h>
#include <botan/basefilt.h>
#include <botan/charset.h>
#include <botan/crc24.h>
/*
* OpenPGP Base64 encoding
*/
string PGP_encode(
	in byte[] input, size_t length,
	in string label,
	const std::map<string, string>& headers)
{
	const string PGP_HEADER = "-----BEGIN PGP " + label + "-----";
	const string PGP_TRAILER = "-----END PGP " + label + "-----";
	const size_t PGP_WIDTH = 64;

	string pgp_encoded = PGP_HEADER;

	if(headers.find("Version") != headers.end())
		pgp_encoded += "Version: " + headers.find("Version")->second + '';

	std::map<string, string>::const_iterator i = headers.begin();
	while(i != headers.end())
	{
		if(i->first != "Version")
			pgp_encoded += i->first + ": " + i->second + '';
		++i;
	}
	pgp_encoded += '';

	Pipe pipe(new Fork(
					 new Base64_Encoder(true, PGP_WIDTH),
					 new Chain(new Hash_Filter(new CRC24), new Base64_Encoder)
					 )
		);

	pipe.process_msg(input, length);

	pgp_encoded += pipe.read_all_as_string(0);
	pgp_encoded += '=' + pipe.read_all_as_string(1) + '';
	pgp_encoded += PGP_TRAILER;

	return pgp_encoded;
}

/*
* OpenPGP Base64 encoding
*/
string PGP_encode(in byte[] input, size_t length,
							  in string type)
{
	std::map<string, string> empty;
	return PGP_encode(input, length, type, empty);
}

/*
* OpenPGP Base64 decoding
*/
SafeArray!byte PGP_decode(DataSource& source,
										string& label,
										std::map<string, string>& headers)
{
	const size_t RANDOM_CHAR_LIMIT = 5;

	const string PGP_HEADER1 = "-----BEGIN PGP ";
	const string PGP_HEADER2 = "-----";
	size_t position = 0;

	while(position != PGP_HEADER1.length())
	{
		byte b;
		if(!source.read_byte(b))
			throw Decoding_Error("PGP: No PGP header found");
		if(b == PGP_HEADER1[position])
			++position;
		else if(position >= RANDOM_CHAR_LIMIT)
			throw Decoding_Error("PGP: Malformed PGP header");
		else
			position = 0;
	}
	position = 0;
	while(position != PGP_HEADER2.length())
	{
		byte b;
		if(!source.read_byte(b))
			throw Decoding_Error("PGP: No PGP header found");
		if(b == PGP_HEADER2[position])
			++position;
		else if(position)
			throw Decoding_Error("PGP: Malformed PGP header");

		if(position == 0)
			label += cast(char)(b);
	}

	headers.clear();
	bool end_of_headers = false;
	while(!end_of_headers)
	{
		string this_header;
		byte b = 0;
		while(b != '')
		{
			if(!source.read_byte(b))
				throw Decoding_Error("PGP: Bad armor header");
			if(b != '')
				this_header += cast(char)(b);
		}

		end_of_headers = true;
		for(size_t j = 0; j != this_header.length(); ++j)
			if(!Charset::is_space(this_header[j]))
				end_of_headers = false;

		if(!end_of_headers)
		{
			string::size_type pos = this_header.find(": ");
			if(pos == string::npos)
				throw Decoding_Error("OpenPGP: Bad headers");

			string key = this_header.substr(0, pos);
			string value = this_header.substr(pos + 2, string::npos);
			headers[key] = value;
		}
	}

	Pipe base64(new Base64_Decoder,
					new Fork(nullptr,
								new Chain(new Hash_Filter(new CRC24),
											 new Base64_Encoder)
						)
		);
	base64.start_msg();

	const string PGP_TRAILER = "-----END PGP " + label + "-----";
	position = 0;
	bool newline_seen = 0;
	string crc;
	while(position != PGP_TRAILER.length())
	{
		byte b;
		if(!source.read_byte(b))
			throw Decoding_Error("PGP: No PGP trailer found");
		if(b == PGP_TRAILER[position])
			++position;
		else if(position)
			throw Decoding_Error("PGP: Malformed PGP trailer");

		if(b == '=' && newline_seen)
		{
			while(b != '')
			{
				if(!source.read_byte(b))
					throw Decoding_Error("PGP: Bad CRC tail");
				if(b != '')
					crc += cast(char)(b);
			}
		}
		else if(b == '')
			newline_seen = true;
		else if(position == 0)
		{
			base64.write(b);
			newline_seen = false;
		}
	}
	base64.end_msg();

	if(crc != "" && crc != base64.read_all_as_string(1))
		throw Decoding_Error("PGP: Corrupt CRC");

	return base64.read_all();
}

/*
* OpenPGP Base64 decoding
*/
SafeArray!byte PGP_decode(DataSource& source, string& label)
{
	std::map<string, string> ignored;
	return PGP_decode(source, label, ignored);
}

}

