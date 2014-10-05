/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.data_src;
import string;
import map;
/**
* @param input the input data
* @param length length of input in bytes
* @param label the human-readable label
* @param headers a set of key/value pairs included in the header
*/
string PGP_encode(
	in ubyte* input,
	size_t length,
	in string label,
	in HashMap!(string, string) headers);

/**
* @param input the input data
* @param length length of input in bytes
* @param label the human-readable label
*/
string PGP_encode(
	in ubyte* input,
	size_t length,
	in string label);

/**
* @param source the input source
* @param label is set to the human-readable label
* @param headers is set to any headers
* @return decoded output as raw binary
*/
SafeVector!ubyte PGP_decode(
	DataSource& source,
	string& label,
	HashMap!(string, string)& headers);

/**
* @param source the input source
* @param label is set to the human-readable label
* @return decoded output as raw binary
*/
SafeVector!ubyte PGP_decode(
	DataSource& source,
	string& label);