/*
* PKCS1 EME
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.eme_pkcs;
/*
* PKCS1 Pad Operation
*/
SafeVector!byte EME_PKCS1v15::pad(in byte* input, size_t inlen,
												 size_t olen,
												 RandomNumberGenerator& rng) const
{
	olen /= 8;

	if (olen < 10)
		throw new Encoding_Error("PKCS1: Output space too small");
	if (inlen > olen - 10)
		throw new Encoding_Error("PKCS1: Input is too large");

	SafeVector!byte output(olen);

	output[0] = 0x02;
	for (size_t j = 1; j != olen - inlen - 1; ++j)
		while(output[j] == 0)
			output[j] = rng.next_byte();
	buffer_insert(output, olen - inlen, input, inlen);

	return output;
}

/*
* PKCS1 Unpad Operation
*/
SafeVector!byte EME_PKCS1v15::unpad(in byte* input, size_t inlen,
													size_t key_len) const
{
	if (inlen != key_len / 8 || inlen < 10 || input[0] != 0x02)
		throw new Decoding_Error("PKCS1::unpad");

	size_t seperator = 0;
	for (size_t j = 0; j != inlen; ++j)
		if (input[j] == 0)
		{
			seperator = j;
			break;
		}
	if (seperator < 9)
		throw new Decoding_Error("PKCS1::unpad");

	return SafeVector!byte(&input[seperator + 1], &input[inlen]);
}

/*
* Return the max input size for a given key size
*/
size_t EME_PKCS1v15::maximum_input_size(size_t keybits) const
{
	if (keybits / 8 > 10)
		return ((keybits / 8) - 10);
	else
		return 0;
}

}
