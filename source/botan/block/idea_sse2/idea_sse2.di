/*
* IDEA in SSE2
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/idea.h>
/**
* IDEA in SSE2
*/
class IDEA_SSE2 : public IDEA
{
	public:
		size_t parallelism() const { return 8; }

		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		BlockCipher* clone() const { return new IDEA_SSE2; }
};