/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine;
/**
* Engine for x86-32 specific implementations
*/
class Assembler_Engine : public Engine
{
	public:
		string provider_name() const { return "asm"; }

		BlockCipher* find_block_cipher(in SCAN_Name,
												 Algorithm_Factory&) const;

		HashFunction* find_hash(in SCAN_Name request,
										Algorithm_Factory&) const;
};