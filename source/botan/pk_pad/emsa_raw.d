/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa_raw;

import botan.pk_pad.emsa;
/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
final class EMSA_Raw : EMSA
{
private:
	/*
	* EMSA-Raw Encode Operation
	*/
	void update(in ubyte* input, size_t length)
	{
		message += Pair(input, length);
	}

	/*
	* Return the raw (unencoded) data
	*/
	Secure_Vector!ubyte raw_data()
	{
		Secure_Vector!ubyte output;
		std.algorithm.swap(message, output);
		return output;
	}

	/*
	* EMSA-Raw Encode Operation
	*/
	Secure_Vector!ubyte encoding_of(in Secure_Vector!ubyte msg,
	                             size_t,
	                             RandomNumberGenerator)
	{
		return msg;
	}

	/*
	* EMSA-Raw Verify Operation
	*/
	bool verify(in Secure_Vector!ubyte coded,
	            in Secure_Vector!ubyte raw,
	            size_t)
	{
		if (coded.length == raw.length)
			return (coded == raw);
		
		if (coded.length > raw.length)
			return false;
		
		// handle zero padding differences
		const size_t leading_zeros_expected = raw.length - coded.length;
		
		bool same_modulo_leading_zeros = true;
		
		for (size_t i = 0; i != leading_zeros_expected; ++i)
			if (raw[i])
				same_modulo_leading_zeros = false;
		
		if (!same_mem(&coded[0], &raw[leading_zeros_expected], coded.length))
			same_modulo_leading_zeros = false;
		
		return same_modulo_leading_zeros;
	}

	Secure_Vector!ubyte message;
}