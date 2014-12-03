/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.aes_isa_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_AES_ISA):

import botan.engine.engine;
import botan.utils.cpuid;
static if (BOTAN_HAS_AES_NI) import botan.block.aes_ni;

/**
* Engine for implementations that hook into CPU-specific
* AES implementations (eg AES-NI, VIA C7, or AMD Geode)
*/
final class AESISAEngine : Engine
{
public:
    string providerName() const { return "aes_isa"; }

    BlockCipher findBlockCipher(in SCANName request,
                                  AlgorithmFactory af) const
    {
        static if (BOTAN_HAS_AES_NI) {
            if (CPUID.hasAesNi())
            {
                if (request.algo_name == "AES-128")
                    return new AES128NI;
                if (request.algo_name == "AES-192")
                    return new AES192NI;
                if (request.algo_name == "AES-256")
                    return new AES256NI;
            }
        }
        
        return null;
    }
}