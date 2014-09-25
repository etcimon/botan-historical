/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/engine.h>
/**
* Engine for x86-32 specific implementations
*/
class Assembler_Engine : public Engine
{
	public:
		string provider_name() const { return "asm"; }

		BlockCipher* find_block_cipher(const SCAN_Name&,
												 Algorithm_Factory&) const;

		HashFunction* find_hash(const SCAN_Name& request,
										Algorithm_Factory&) const;
};