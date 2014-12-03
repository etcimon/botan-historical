/*
* PK Key Factory
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pk_algs;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.pubkey.pk_keys;
import botan.asn1.oids;

static if (BOTAN_HAS_RSA)                  import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)                  import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_DIFFIE_HELLMAN)      import botan.pubkey.algo.dh;
static if (BOTAN_HAS_ECDSA)              import botan.pubkey.algo.ecdsa;
static if (BOTAN_HAS_GOST_34_10_2001)     import botan.pubkey.algo.gost_3410;
static if (BOTAN_HAS_NYBERG_RUEPPEL)      import botan.pubkey.algo.nr;
static if (BOTAN_HAS_RW)                  import botan.pubkey.algo.rw;
static if (BOTAN_HAS_ELGAMAL)              import botan.pubkey.algo.elgamal;
static if (BOTAN_HAS_ECDH)                 import botan.pubkey.algo.ecdh;

PublicKey makePublicKey(in AlgorithmIdentifier alg_id,
                           in SecureVector!ubyte key_bits)
{
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "")
        throw new DecodingError("Unknown algorithm OID: " ~ alg_id.oid.toString());
    
    static if (BOTAN_HAS_RSA) {
        if (alg_name == "RSA")
            return new RSAPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_RW) {
        if (alg_name == "RW")
            return new RWPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_DSA) {
        if (alg_name == "DSA")
            return new DSAPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_DIFFIE_HELLMAN) {
        if (alg_name == "DH")
            return new DHPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_NYBERG_RUEPPEL) {
        if (alg_name == "NR")
            return new NRPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_ELGAMAL) {
        if (alg_name == "ElGamal")
            return new ElGamalPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_ECDSA) {
        if (alg_name == "ECDSA")
            return new ECDSAPublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_GOST_34_10_2001) {
        if (alg_name == "GOST-34.10")
            return new GOST3410PublicKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_ECDH) {
        if (alg_name == "ECDH")
            return new ECDHPublicKey(alg_id, key_bits);
    }
    
    return null;
}

PrivateKey makePrivateKey(in AlgorithmIdentifier alg_id,
                             in SecureVector!ubyte key_bits,
                             RandomNumberGenerator rng)
{
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "")
        throw new DecodingError("Unknown algorithm OID: " ~ alg_id.oid.toString());
    
    static if (BOTAN_HAS_RSA) {
        if (alg_name == "RSA")
            return new RSAPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_RW) {
        if (alg_name == "RW")
            return new RWPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_DSA) {
        if (alg_name == "DSA")
            return new DSAPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_DIFFIE_HELLMAN) {
        if (alg_name == "DH")
            return new DHPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_NYBERG_RUEPPEL) {
        if (alg_name == "NR")
            return new NRPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_ELGAMAL) {
        if (alg_name == "ElGamal")
            return new ElGamalPrivateKey(alg_id, key_bits, rng);
    }
    
    static if (BOTAN_HAS_ECDSA) {
        if (alg_name == "ECDSA")
            return new ECDSAPrivateKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_GOST_34_10_2001) {
        if (alg_name == "GOST-34.10")
            return new GOST3410PrivateKey(alg_id, key_bits);
    }
    
    static if (BOTAN_HAS_ECDH) {
        if (alg_name == "ECDH")
            return new ECDHPrivateKey(alg_id, key_bits);
    }
    
    return null;
}