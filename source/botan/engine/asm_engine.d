/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.asm_engine;

import botan.engine.engine;

version(BOTAN_HAS_SERPENT_X86_32) 	import botan.block.serp_x86_32;
version(BOTAN_HAS_MD4_X86_32) 		import botan.md4_x86_32;
version(BOTAN_HAS_MD5_X86_32) 		import botan.md5_x86_32;
version(BOTAN_HAS_SHA1_X86_64)		import botan.sha1_x86_64;
version(BOTAN_HAS_SHA1_X86_32)		import botan.sha1_x86_32;

/**
* Engine for x86-32 specific implementations
*/
class Assembler_Engine : Engine
{
public:
	string provider_name() const { return "asm"; }

		
	BlockCipher find_block_cipher(	in SCAN_Name request,
	                             			Algorithm_Factory af) const
	{
		version(BOTAN_HAS_SERPENT_X86_32) { 
			if (request.algo_name() == "Serpent")
			{
				
				return new Serpent_X86_32;
			}
		}
		return null;
	}

	HashFunction find_hash(in SCAN_Name request,
	                                Algorithm_Factory af) const
	{
		version(BOTAN_HAS_MD4_X86_32) {
			if (request.algo_name() == "MD4")
				return new MD4_X86_32;
		}
		
		version(BOTAN_HAS_MD5_X86_32) {
			if (request.algo_name() == "MD5")
				return new MD5_X86_32;
		}
		
		if (request.algo_name() == "SHA-160")
		{
			version(BOTAN_HAS_SHA1_X86_64)
				return new SHA_160_X86_64;
			else version(BOTAN_HAS_SHA1_X86_32)
				return new SHA_160_X86_32;
		}
		
		return null;
	}
};