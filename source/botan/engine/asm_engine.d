/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.asm_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_ASSEMBLER):

import botan.engine.engine;

static if (BOTAN_HAS_SERPENT_X86_32)     import botan.block.serp_x86_32;
static if (BOTAN_HAS_MD4_X86_32)         import botan.hash.md4_x86_32;
static if (BOTAN_HAS_MD5_X86_32)         import botan.hash.md5_x86_32;
static if (BOTAN_HAS_SHA1_X86_64)        import botan.hash.sha1_x86_64;
static if (BOTAN_HAS_SHA1_X86_32)        import botan.hash.sha1_x86_32;

/**
* Engine for x86-32 specific implementations
*/
final class AssemblerEngine : Engine
{
public:
    string providerName() const { return "asm"; }

    BlockCipher findBlockCipher(in SCANToken request,
                                AlgorithmFactory af) const
    {
        static if (BOTAN_HAS_SERPENT_X86_32) { 
            if (request.algoName == "Serpent")
            {
                
                return new Serpent_X86_32;
            }
        }
        return null;
    }

    HashFunction findHash(in SCANToken request,
                          AlgorithmFactory af) const
    {
        static if (BOTAN_HAS_MD4_X86_32) {
            if (request.algoName == "MD4")
                return new MD4_X86_32;
        }
        
        static if (BOTAN_HAS_MD5_X86_32) {
            if (request.algoName == "MD5")
                return new MD5_X86_32;
        }
        
        if (request.algoName == "SHA-160")
        {
            static if (BOTAN_HAS_SHA1_X86_64)
                return new SHA160_X86_64;
            else static if (BOTAN_HAS_SHA1_X86_32)
                return new SHA160_X86_32;
        }
        
        return null;
    }

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