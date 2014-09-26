/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mgf1.h>
#include <botan/exceptn.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>
void mgf1_mask(HashFunction& hash,
					in byte* input,
					byte* output)
{
	size_t in_len = input.length;
	size_t out_len = output.length;
	uint counter = 0;

	while(out_len)
	{
		hash.update(input, in_len);
		hash.update_be(counter);
		SafeVector!byte buffer = hash.flush();

		size_t xored = std::min<size_t>(buffer.size(), out_len);
		xor_buf(out, &buffer[0], xored);
		out += xored;
		out_len -= xored;

		++counter;
	}
}

}
