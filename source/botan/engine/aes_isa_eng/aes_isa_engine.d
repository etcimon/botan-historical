/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.aes_isa_engine;
import botan.cpuid;

#if defined(BOTAN_HAS_AES_NI)
  import botan.block.aes_ni.aes_ni;
#endif
BlockCipher
AES_ISA_Engine::find_block_cipher(in SCAN_Name request,
											 Algorithm_Factory) const
{
#if defined(BOTAN_HAS_AES_NI)
	if (CPUID::has_aes_ni())
	{
		if (request.algo_name() == "AES-128")
			return new AES_128_NI;
		if (request.algo_name() == "AES-192")
			return new AES_192_NI;
		if (request.algo_name() == "AES-256")
			return new AES_256_NI;
	}
#endif

	return null;
}

}
