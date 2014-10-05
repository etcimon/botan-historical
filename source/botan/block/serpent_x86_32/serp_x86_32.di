/*
* Serpent in x86-32 asm
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.serpent;
/**
* Serpent implementation in x86-32 assembly
*/
class Serpent_X86_32 : public Serpent
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		BlockCipher clone() const { return new Serpent_X86_32; }
	private:
		void key_schedule(in ubyte*, size_t);
};