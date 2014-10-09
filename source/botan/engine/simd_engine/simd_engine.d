/*
* SIMD Assembly Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.simd_engine.simd_engine;
import botan.engine.engine;
import botan.simd.simd_32;
import botan.cpuid;

/**
* Engine for implementations that use some kind of SIMD
*/
class SIMD_Engine : Engine
{
public:
	string provider_name() const { return "simd"; }

	BlockCipher find_block_cipher(in SCAN_Name request,
	                              Algorithm_Factory) const
	{
		version(BOTAN_HAS_AES_SSSE3) {
			if (request.algo_name() == "AES-128" && CPUID::has_ssse3())
				return new AES_128_SSSE3;
			if (request.algo_name() == "AES-192" && CPUID::has_ssse3())
				return new AES_192_SSSE3;
			if (request.algo_name() == "AES-256" && CPUID::has_ssse3())
				return new AES_256_SSSE3;
		}
		
		version(BOTAN_HAS_IDEA_SSE2) {
			if (request.algo_name() == "IDEA" && CPUID::has_sse2())
				return new IDEA_SSE2;
		}
		
		version(BOTAN_HAS_NOEKEON_SIMD) {
			if (request.algo_name() == "Noekeon" && SIMD_32.enabled())
				return new Noekeon_SIMD;
		}
		
		version(BOTAN_HAS_THREEFISH_512_AVX2) {
			if (request.algo_name() == "Threefish-512" && CPUID::has_avx2())
				return new Threefish_512_AVX2;
		}
		
		version(BOTAN_HAS_SERPENT_SIMD) {
			if (request.algo_name() == "Serpent" && SIMD_32.enabled())
				return new Serpent_SIMD;
		}
		
		version(BOTAN_HAS_XTEA_SIMD) {
			if (request.algo_name() == "XTEA" && SIMD_32.enabled())
				return new XTEA_SIMD;
		}
		
		return null;
	}

	HashFunction find_hash(in SCAN_Name request,
	                       Algorithm_Factory) const
	{
		version(BOTAN_HAS_SHA1_SSE2) {
			if (request.algo_name() == "SHA-160" && CPUID::has_sse2())
				return new SHA_160_SSE2;
		}
		
		BOTAN_UNUSED(request);
		
		return null;
	}
};

version(BOTAN_HAS_AES_SSSE3) {
	import botan.block.aes_ssse3.aes_ssse3;
}

version(BOTAN_HAS_SERPENT_SIMD) {
	import botan.serp_simd;
}

version(BOTAN_HAS_THREEFISH_512_AVX2) {
	import botan.threefish_avx2;
}

version(BOTAN_HAS_NOEKEON_SIMD) {
	import botan.block.noekeon_simd.noekeon_simd;
}

version(BOTAN_HAS_XTEA_SIMD) {
	import botan.xtea_simd;
}

version(BOTAN_HAS_IDEA_SSE2) {
	import botan.block.idea_sse2.idea_sse2;
}

version(BOTAN_HAS_SHA1_SSE2) {
	import botan.sha1_sse2;
}


