/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <string>
/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void hex_encode(char output[],
								  in byte[] input,
								  size_t input_length,
								  bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
string hex_encode(in byte[] input,
											size_t input_length,
											bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
template<typename Alloc>
string hex_encode(in Vector!( byte, Alloc ) input,
							  bool uppercase = true)
{
	return hex_encode(&input[0], input.size(), uppercase);
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*		  bytes of input were actually consumed. If less than
*		  input_length, then the range input[consumed:length]
*		  should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(byte output[],
									 const char input[],
									 size_t input_length,
									 size_t& input_consumed,
									 bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(byte output[],
									 const char input[],
									 size_t input_length,
									 bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t hex_decode(byte output[],
									 in string input,
									 bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Vector!( byte ) BOTAN_DLL
hex_decode(const char input[],
			  size_t input_length,
			  bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
Vector!( byte ) BOTAN_DLL
hex_decode(in string input,
			  bool ignore_ws = true);/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
SafeVector!byte BOTAN_DLL
hex_decode_locked(const char input[],
						size_t input_length,
						bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded hex output
*/
SafeVector!byte BOTAN_DLL
hex_decode_locked(in string input,
						bool ignore_ws = true);