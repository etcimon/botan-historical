/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PEM_H__
#define BOTAN_PEM_H__

#include <botan/data_src.h>

namespace Botan {

namespace PEM_Code {

/**
* Encode some binary data in PEM format
*/
BOTAN_DLL string encode(const byte data[],
									  size_t data_len,
									  in string label,
									  size_t line_width = 64);

/**
* Encode some binary data in PEM format
*/
inline string encode(in Array!byte data,
								  in string label,
								  size_t line_width = 64)
	{
	return encode(&data[0], data.size(), label, line_width);
	}

/**
* Encode some binary data in PEM format
*/
inline string encode(in SafeArray!byte data,
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
BOTAN_DLL SafeArray!byte decode(DataSource& pem,
												 string& label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/
BOTAN_DLL SafeArray!byte decode(in string pem,
												 string& label);

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is what we expect the label to be
*/
BOTAN_DLL SafeArray!byte decode_check_label(
	DataSource& pem,
	in string label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is what we expect the label to be
*/
BOTAN_DLL SafeArray!byte decode_check_label(
	in string pem,
	in string label);

/**
* Heuristic test for PEM data.
*/
BOTAN_DLL bool matches(DataSource& source,
							  in string extra = "",
							  size_t search_range = 4096);

}

}

#endif
