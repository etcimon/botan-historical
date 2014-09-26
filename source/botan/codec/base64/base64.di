/*
* Base64 Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <string>
/**
* Perform base64 encoding
* @param output an array of at least input_length*4/3 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*		  bytes of input were actually consumed. If less than
*		  input_length, then the range input[consumed:length]
*		  should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
			padding chars will be applied if needed
* @return number of bytes written to output
*/
size_t base64_encode(char* output,
					 in byte* input,
					 size_t input_length,
					 size_t& input_consumed,
					 bool final_inputs);

/**
* Perform base64 encoding
* @param input some input
* @param input_length length of input in bytes
* @return base64adecimal representation of input
*/
string base64_encode(in byte* input,
					size_t input_length);

/**
* Perform base64 encoding
* @param input some input
* @return base64adecimal representation of input
*/
string base64_encode(Alloc)(in Vector!( byte, Alloc ) input)
{
	return base64_encode(&input[0], input.size());
}

/**
* Perform base64 decoding
* @param output an array of at least input_length*3/4 bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*		  bytes of input were actually consumed. If less than
*		  input_length, then the range input[consumed:length]
*		  should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
			padding is allowed
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t base64_decode(byte* output,
					 in char* input,
					 size_t input_length,
					 ref size_t input_consumed,
					 bool final_inputs,
					 bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least input_length*3/4 bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t base64_decode(byte* output,
					 const char* input,
					 size_t input_length,
					 bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least input_length/3*4 bytes
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t base64_decode(byte* output,
					 in string input,
					 bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded base64 output
*/
SafeVector!byte base64_decode(const char* input,
							 size_t input_length,
							 bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw new an
						 exception if whitespace is encountered
* @return decoded base64 output
*/
SafeVector!byte base64_decode(in string input,
							 bool ignore_ws = true);