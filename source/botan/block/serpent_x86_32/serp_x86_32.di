/*
* Serpent in x86-32 asm
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/serpent.h>
/**
* Serpent implementation in x86-32 assembly
*/
class Serpent_X86_32 : public Serpent
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		BlockCipher* clone() const { return new Serpent_X86_32; }
	private:
		void key_schedule(const byte[], size_t);
};