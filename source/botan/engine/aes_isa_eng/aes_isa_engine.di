/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine.engine;
/**
* Engine for implementations that hook into CPU-specific
* AES implementations (eg AES-NI, VIA C7, or AMD Geode)
*/
class AES_ISA_Engine : Engine
{
	public:
		string provider_name() const { return "aes_isa"; }

		BlockCipher find_block_cipher(in SCAN_Name,
												 Algorithm_Factory) const;
};