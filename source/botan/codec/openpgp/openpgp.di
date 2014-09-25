/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_OPENPGP_CODEC_H__

#include <botan/data_src.h>
#include <string>
#include <map>
/**
* @param input the input data
* @param length length of input in bytes
* @param label the human-readable label
* @param headers a set of key/value pairs included in the header
*/
string PGP_encode(
	const byte input[],
	size_t length,
	in string label,
	const std::map<string, string>& headers);

/**
* @param input the input data
* @param length length of input in bytes
* @param label the human-readable label
*/
string PGP_encode(
	const byte input[],
	size_t length,
	in string label);

/**
* @param source the input source
* @param label is set to the human-readable label
* @param headers is set to any headers
* @return decoded output as raw binary
*/
SafeArray!byte PGP_decode(
	DataSource& source,
	string& label,
	std::map<string, string>& headers);

/**
* @param source the input source
* @param label is set to the human-readable label
* @return decoded output as raw binary
*/
SafeArray!byte PGP_decode(
	DataSource& source,
	string& label);