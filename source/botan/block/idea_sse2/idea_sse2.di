/*
* IDEA in SSE2
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.idea;
/**
* IDEA in SSE2
*/
class IDEA_SSE2 : public IDEA
{
	public:
		size_t parallelism() const { return 8; }

		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		BlockCipher* clone() const { return new IDEA_SSE2; }
};