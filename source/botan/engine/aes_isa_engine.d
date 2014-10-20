/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.aes_isa_engine;

import botan.engine.engine;
import botan.utils.cpuid;
static if (BOTAN_HAS_AES_NI) import botan.block.aes_ni;

/**
* Engine for implementations that hook into CPU-specific
* AES implementations (eg AES-NI, VIA C7, or AMD Geode)
*/
class AES_ISA_Engine : Engine
{
public:
	string provider_name() const { return "aes_isa"; }

	BlockCipher find_block_cipher(in SCAN_Name request,
	                              AlgorithmFactory af) const
	{
		static if (BOTAN_HAS_AES_NI) {
			if (CPUID.has_aes_ni())
			{
				if (request.algo_name() == "AES-128")
					return new AES_128_NI;
				if (request.algo_name() == "AES-192")
					return new AES_192_NI;
				if (request.algo_name() == "AES-256")
					return new AES_256_NI;
			}
		}
		
		return null;
	}
};