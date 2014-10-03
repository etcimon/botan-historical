/*
* SIMD Assembly Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine;
/**
* Engine for implementations that use some kind of SIMD
*/
class SIMD_Engine : public Engine
{
	public:
		string provider_name() const { return "simd"; }

		BlockCipher find_block_cipher(in SCAN_Name,
												 ref Algorithm_Factory) const;

		HashFunction find_hash(in SCAN_Name request,
										ref Algorithm_Factory) const;
};