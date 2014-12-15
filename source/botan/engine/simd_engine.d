/*
* SIMD Assembly Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.simd_engine.simd_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_SIMD):

import botan.engine.engine;
import botan.simd.simd_32;
import botan.utils.cpuid;

static if (BOTAN_HAS_AES_SSSE3)         import botan.block.aes_ssse3;
static if (BOTAN_HAS_SERPENT_SIMD)     import botan.block.serp_simd;
static if (BOTAN_HAS_THREEFISH_512_AVX2)import botan.block.threefish_avx2;
static if (BOTAN_HAS_NOEKEON_SIMD)     import botan.block.noekeon_simd;
static if (BOTAN_HAS_XTEA_SIMD)         import botan.block.xtea_simd;
static if (BOTAN_HAS_IDEA_SSE2)         import botan.block.idea_sse2;
static if (BOTAN_HAS_SHA1_SSE2)         import botan.hash.sha1_sse2;

/**
* Engine for implementations that use some kind of SIMD
*/
final class SIMDEngine : Engine
{
public:
    string providerName() const { return "simd"; }

    BlockCipher findBlockCipher(in SCANToken request,
                                AlgorithmFactoryImpl) const
    {
        static if (BOTAN_HAS_AES_SSSE3) {
            if (request.algoName == "AES-128" && CPUID.hasSsse3())
                return new AES128_SSSE3;
            if (request.algoName == "AES-192" && CPUID.hasSsse3())
                return new AES192_SSSE3;
            if (request.algoName == "AES-256" && CPUID.hasSsse3())
                return new AES256_SSSE3;
        }
        
        static if (BOTAN_HAS_IDEA_SSE2) {
            if (request.algoName == "IDEA" && CPUID.hasSse2())
                return new IDEASSE2;
        }
        
        static if (BOTAN_HAS_NOEKEON_SIMD) {
            if (request.algoName == "Noekeon" && SIMD32.enabled())
                return new NoekeonSIMD;
        }
        
        static if (BOTAN_HAS_THREEFISH_512_AVX2) {
            if (request.algoName == "Threefish-512" && CPUID.hasAvx2())
                return new Threefish512AVX2;
        }
        
        static if (BOTAN_HAS_SERPENT_SIMD) {
            if (request.algoName == "Serpent" && SIMD32.enabled())
                return new SerpentSIMD;
        }
        
        static if (BOTAN_HAS_XTEA_SIMD) {
            if (request.algoName == "XTEA" && SIMD32.enabled())
                return new XTEASIMD;
        }
        
        return null;
    }

    HashFunction findHash(in SCANToken request,
                          AlgorithmFactoryImpl) const
    {
        static if (BOTAN_HAS_SHA1_SSE2) {
            if (request.algoName == "SHA-160" && CPUID.hasSse2())
                return new SHA160SSE2;
        }

        return null;
    }
}
