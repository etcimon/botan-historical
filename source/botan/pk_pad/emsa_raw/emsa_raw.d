/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.emsa_raw;
/*
* EMSA-Raw Encode Operation
*/
void EMSA_Raw::update(in ubyte* input, size_t length)
{
	message += Pair(input, length);
}

/*
* Return the raw (unencoded) data
*/
SafeVector!ubyte EMSA_Raw::raw_data()
{
	SafeVector!ubyte output;
	std::swap(message, output);
	return output;
}

/*
* EMSA-Raw Encode Operation
*/
SafeVector!ubyte EMSA_Raw::encoding_of(in SafeVector!ubyte msg,
													  size_t,
													  RandomNumberGenerator)
{
	return msg;
}

/*
* EMSA-Raw Verify Operation
*/
bool EMSA_Raw::verify(in SafeVector!ubyte coded,
							 in SafeVector!ubyte raw,
							 size_t)
{
	if (coded.size() == raw.size())
		return (coded == raw);

	if (coded.size() > raw.size())
		return false;

	// handle zero padding differences
	const size_t leading_zeros_expected = raw.size() - coded.size();

	bool same_modulo_leading_zeros = true;

	for (size_t i = 0; i != leading_zeros_expected; ++i)
		if (raw[i])
			same_modulo_leading_zeros = false;

	if (!same_mem(&coded[0], &raw[leading_zeros_expected], coded.size()))
		same_modulo_leading_zeros = false;

	return same_modulo_leading_zeros;
}

}
