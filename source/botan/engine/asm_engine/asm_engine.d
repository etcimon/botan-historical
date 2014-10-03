/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.asm_engine;

#if defined(BOTAN_HAS_SERPENT_X86_32)
  import botan.serp_x86_32;
#endif

#if defined(BOTAN_HAS_MD4_X86_32)
  import botan.md4_x86_32;
#endif

#if defined(BOTAN_HAS_MD5_X86_32)
  import botan.md5_x86_32;
#endif

#if defined(BOTAN_HAS_SHA1_X86_64)
  import botan.sha1_x86_64;
#endif

#if defined(BOTAN_HAS_SHA1_X86_32)
  import botan.sha1_x86_32;
#endif
BlockCipher
Assembler_Engine::find_block_cipher(in SCAN_Name request,
												ref Algorithm_Factory) const
{
	if (request.algo_name() == "Serpent")
	{
#if defined(BOTAN_HAS_SERPENT_X86_32)
		return new Serpent_X86_32;
#endif
	}

	return null;
}

HashFunction
Assembler_Engine::find_hash(in SCAN_Name request,
									 ref Algorithm_Factory) const
{
#if defined(BOTAN_HAS_MD4_X86_32)
	if (request.algo_name() == "MD4")
		return new MD4_X86_32;
#endif

#if defined(BOTAN_HAS_MD5_X86_32)
	if (request.algo_name() == "MD5")
		return new MD5_X86_32;
#endif

	if (request.algo_name() == "SHA-160")
	{
#if defined(BOTAN_HAS_SHA1_X86_64)
			return new SHA_160_X86_64;
#elif defined(BOTAN_HAS_SHA1_X86_32)
			return new SHA_160_X86_32;
#endif
	}

	return null;
}

}
