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

    BlockCipher findBlockCipher(in SCANToken request,
                                AlgorithmFactory af) const
    {
        static if (BOTAN_HAS_AES_NI) {
            if (CPUID.hasAesNi())
            {
                if (request.algoName == "AES-128")
                    return new AES128NI;
                if (request.algoName == "AES-192")
                    return new AES192NI;
                if (request.algoName == "AES-256")
                    return new AES256NI;
            }
        }
        
        return null;
    }

    HashFunction findHash(in SCANToken request, AlgorithmFactory af) const
    { assert(false); }

    StreamCipher findStreamCipher(in SCANToken algo_spec, AlgorithmFactory af) const
    { assert(false); }
    
    MessageAuthenticationCode findMac(in SCANToken algo_spec, AlgorithmFactory af) const
    { assert(false); }
    
    PBKDF findPbkdf(in SCANToken algo_spec, AlgorithmFactory af) const
    { assert(false); }
    
    ModularExponentiator modExp(in BigInt n, PowerMod.UsageHints hints) const
    { assert(false); }
    
    KeyedFilter getCipher(in string algo_spec, CipherDir dir, AlgorithmFactory af) const
    { assert(false); }
    
    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const
    { assert(false); }
    
    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const
    { assert(false); }
    
    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const
    { assert(false); }
    
    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator rng) const
    { assert(false); }
    
    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const
    { assert(false); }
}