/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.data_src;
namespace PEM_Code {

/**
* Encode some binary data in PEM format
*/
string encode(in ubyte* data,
									  size_t data_len,
									  in string label,
									  size_t line_width = 64);

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
SafeVector!ubyte decode(DataSource& pem,
												 string& label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/
SafeVector!ubyte decode(in string pem,
												 string& label);

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is what we expect the label to be
*/
SafeVector!ubyte decode_check_label(
	DataSource& pem,
	in string label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is what we expect the label to be
*/
SafeVector!ubyte decode_check_label(
	in string pem,
	in string label);

/**
* Heuristic test for PEM data.
*/
bool matches(DataSource& source,
							  in string extra = "",
							  size_t search_range = 4096);

}