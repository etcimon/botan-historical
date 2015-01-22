/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.engine;

import botan.constants;
public import botan.algo_base.scan_token;
public import botan.block.block_cipher;
public import botan.stream.stream_cipher;
public import botan.hash.hash;
public import botan.mac.mac;
public import botan.pbkdf.pbkdf;
public import botan.math.numbertheory.pow_mod;
public import botan.pubkey.pk_keys;
public import botan.pubkey.pk_ops;
public import botan.rng.rng;
public import botan.math.bigint.bigint;
public import botan.filters.key_filt;
public import botan.algo_factory.algo_factory;
public import botan.utils.types;

/**
* Base class for all engines. All non-pure abstract functions simply
* return NULL, indicating the algorithm in question is not
* supported. Subclasses can reimplement whichever function(s)
* they want to hook in a particular type.
*/
interface Engine
{
public:
    /**
    * @return name of this engine
    */
    string providerName() const;

    /**
    * @param algo_spec = the algorithm name/specification
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    BlockCipher findBlockCipher(in SCANToken algo_spec, AlgorithmFactory af) const;


    /**
    * @param algo_spec = the algorithm name/specification
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    StreamCipher findStreamCipher(in SCANToken algo_spec, AlgorithmFactory af) const;

    /**
    * @param algo_spec = the algorithm name/specification
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    HashFunction findHash(in SCANToken algo_spec, AlgorithmFactory af) const;


    /**
    * @param algo_spec = the algorithm name/specification
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    MessageAuthenticationCode findMac(in SCANToken algo_spec, AlgorithmFactory af) const;

    /**
    * @param algo_spec = the algorithm name/specification
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    PBKDF findPbkdf(in SCANToken algo_spec, AlgorithmFactory af) const;

    /**
    * Return a new cipher object
    * @param algo_spec = the algorithm name/specification
    * @param dir = specifies if encryption or decryption is desired
    * @param af = an algorithm factory object
    * @return newly allocated object, or NULL
    */
    KeyedFilter getCipher(in string algo_spec, CipherDir dir, AlgorithmFactory af) const;

    static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

    /**
    * @param n = the modulus
    * @param hints = any use hints
    * @return newly allocated object, or NULL
    */
    ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints hints) const;


    /**
    * Return a new operator object for this key, if possible
    * @param key = the key we want an operator for
    * @return newly allocated operator object, or NULL
    */
    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const;

    /**
    * Return a new operator object for this key, if possible
    * @param key = the key we want an operator for
    * @return newly allocated operator object, or NULL
    */
    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const;

    /**
    * Return a new operator object for this key, if possible
    * @param key = the key we want an operator for
    * @return newly allocated operator object, or NULL
    */
    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const;

    /**
    * Return a new operator object for this key, if possible
    * @param key = the key we want an operator for
    * @return newly allocated operator object, or NULL
    */
    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator rng) const;

    /**
    * Return a new operator object for this key, if possible
    * @param key = the key we want an operator for
    * @return newly allocated operator object, or NULL
    */
    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const;
}
