/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pem;
import botan.filters;
import botan.parsing;
namespace PEM_Code {

/*
* PEM encode BER/DER-encoded objects
*/
string encode(in byte* der, size_t length, in string label,
						 size_t width)
{
	const string PEM_HEADER = "-----BEGIN " ~ label ~ "-----";
	const string PEM_TRAILER = "-----END " ~ label ~ "-----";

	Pipe pipe(new Base64_Encoder(true, width));
	pipe.process_msg(der, length);
	return (PEM_HEADER + pipe.read_all_as_string() + PEM_TRAILER);
}

/*
* Decode PEM down to raw BER/DER
*/
SafeVector!byte decode_check_label(DataSource& source,
												  in string label_want)
{
	string label_got;
	SafeVector!byte ber = decode(source, label_got);
	if (label_got != label_want)
		throw new Decoding_Error("PEM: Label mismatch, wanted " ~ label_want +
									", got " ~ label_got);
	return ber;
}

/*
* Decode PEM down to raw BER/DER
*/
SafeVector!byte decode(DataSource& source, string& label)
{
	const size_t RANDOM_CHAR_LIMIT = 8;

	const string PEM_HEADER1 = "-----BEGIN ";
	const string PEM_HEADER2 = "-----";
	size_t position = 0;

	while(position != PEM_HEADER1.length())
	{
		byte b;
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
		byte b;
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
		byte b;
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

SafeVector!byte decode_check_label(in string pem,
												  in string label_want)
{
	DataSource_Memory src(pem);
	return decode_check_label(src, label_want);
}

SafeVector!byte decode(in string pem, string& label)
{
	DataSource_Memory src(pem);
	return decode(src, label);
}

/*
* Search for a PEM signature
*/
bool matches(DataSource& source, in string extra,
				 size_t search_range)
{
	const string PEM_HEADER = "-----BEGIN " ~ extra;

	SafeVector!byte search_buf(search_range);
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

}

}
