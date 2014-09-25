/*
* Serpent in x86-32 asm
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_SERPENT_X86_32_H__

#include <botan/serpent.h>
/**
* Serpent implementation in x86-32 assembly
*/
class Serpent_X86_32 : public Serpent
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		BlockCipher* clone() const { return new Serpent_X86_32; }
	private:
		void key_schedule(const byte[], size_t);
};