/*
* MGF1
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.mgf1;

import botan.kdf.kdf;
import botan.hash.hash;
import botan.utils.exceptn;
import botan.internal.xor_buf;
import std.algorithm;

/**
* MGF1 from PKCS #1 v2.0
*/
void mgf1_mask(HashFunction hash,
               in ubyte* input,
               ubyte* output)
{
	size_t in_len = input.length;
	size_t out_len = output.length;
	uint counter = 0;
	
	while(out_len)
	{
		hash.update(input, in_len);
		hash.update_be(counter);
		SafeVector!ubyte buffer = hash.flush();
		
		size_t xored = std.algorithm.min(buffer.length, out_len);
		xor_buf(output, &buffer[0], xored);
		output += xored;
		out_len -= xored;
		
		++counter;
	}
}