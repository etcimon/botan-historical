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
void EMSA_Raw::update(in byte* input, size_t length)
{
	message += Pair(input, length);
}

/*
* Return the raw (unencoded) data
*/
SafeVector!byte EMSA_Raw::raw_data()
{
	SafeVector!byte output;
	std::swap(message, output);
	return output;
}

/*
* EMSA-Raw Encode Operation
*/
SafeVector!byte EMSA_Raw::encoding_of(in SafeVector!byte msg,
													  size_t,
													  RandomNumberGenerator&)
{
	return msg;
}

/*
* EMSA-Raw Verify Operation
*/
bool EMSA_Raw::verify(in SafeVector!byte coded,
							 in SafeVector!byte raw,
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
