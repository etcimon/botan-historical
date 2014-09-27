/*
* SIMD Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.simd_engine;
import botan.internal.simd_32;
import botan.cpuid;

#if defined(BOTAN_HAS_AES_SSSE3)
  import botan.aes_ssse3;
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
  import botan.serp_simd;
#endif

#if defined(BOTAN_HAS_THREEFISH_512_AVX2)
  import botan.threefish_avx2;
#endif

#if defined(BOTAN_HAS_NOEKEON_SIMD)
  import botan.noekeon_simd;
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
  import botan.xtea_simd;
#endif

#if defined(BOTAN_HAS_IDEA_SSE2)
  import botan.idea_sse2;
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
  import botan.sha1_sse2;
#endif
BlockCipher*
SIMD_Engine::find_block_cipher(in SCAN_Name request,
										 Algorithm_Factory&) const
{
#if defined(BOTAN_HAS_AES_SSSE3)
	if (request.algo_name() == "AES-128" && CPUID::has_ssse3())
		return new AES_128_SSSE3;
	if (request.algo_name() == "AES-192" && CPUID::has_ssse3())
		return new AES_192_SSSE3;
	if (request.algo_name() == "AES-256" && CPUID::has_ssse3())
		return new AES_256_SSSE3;
#endif

#if defined(BOTAN_HAS_IDEA_SSE2)
	if (request.algo_name() == "IDEA" && CPUID::has_sse2())
		return new IDEA_SSE2;
#endif

#if defined(BOTAN_HAS_NOEKEON_SIMD)
	if (request.algo_name() == "Noekeon" && SIMD_32::enabled())
		return new Noekeon_SIMD;
#endif

#if defined(BOTAN_HAS_THREEFISH_512_AVX2)
	if (request.algo_name() == "Threefish-512" && CPUID::has_avx2())
		return new Threefish_512_AVX2;
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
	if (request.algo_name() == "Serpent" && SIMD_32::enabled())
		return new Serpent_SIMD;
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
	if (request.algo_name() == "XTEA" && SIMD_32::enabled())
		return new XTEA_SIMD;
#endif

	return null;
}

HashFunction*
SIMD_Engine::find_hash(in SCAN_Name request,
							  Algorithm_Factory&) const
{
#if defined(BOTAN_HAS_SHA1_SSE2)
	if (request.algo_name() == "SHA-160" && CPUID::has_sse2())
		return new SHA_160_SSE2;
#endif

	BOTAN_UNUSED(request);

	return null;
}

}
