/*
* PBE Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbe.factory;

import botan.pbe.pbe;
import botan.utils.types;
// import string;
import std.datetime;
import botan.asn1.oids;
import botan.algo_base.scan_name;
import botan.rng.rng;
import botan.utils.parsing;
import botan.libstate.libstate;
import std.datetime;

static if (BOTAN_HAS_PBE_PKCS_V20) {
    import botan.pbe.pbes2;
    import botan.mac.hmac;
}

/**
* Factory function for PBEs.
* @param algo_spec = the name of the PBE algorithm to retrieve
* @param passphrase = the passphrase to use for encryption
* @param msec = how many milliseconds to run the PBKDF
* @param rng = a random number generator
* @return pointer to a PBE with randomly created parameters
*/
PBE getPbe(in string algo_spec,
            in string passphrase,
            Duration dur,
            RandomNumberGenerator rng)
{
    SCANToken request = SCANToken(algo_spec);
    
    const string pbe = request.algo_name;
    string digest_name = request.arg(0);
    const string cipher = request.arg(1);
    
    Vector!string cipher_spec = splitter(cipher, '/');
    if (cipher_spec.length != 2)
        throw new InvalidArgument("PBE: Invalid cipher spec " ~ cipher);
    
    const string cipher_algo = SCANToken.derefAlias(cipher_spec[0]);
    const string cipher_mode = cipher_spec[1];
    
    if (cipher_mode != "CBC")
        throw new InvalidArgument("PBE: Invalid cipher mode " ~ cipher);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const BlockCipher block_cipher = af.prototypeBlockCipher(cipher_algo);
    if (!block_cipher)
        throw new AlgorithmNotFound(cipher_algo);
    
    const HashFunction hash_function = af.prototypeHashFunction(digest_name);
    if (!hash_function)
        throw new AlgorithmNotFound(digest_name);
    
    if (request.argCount() != 2)
        throw new InvalidAlgorithmName(algo_spec);
    
    static if (BOTAN_HAS_PBE_PKCS_V20) {
        if (pbe == "PBE-PKCS5v20")
            return new PBEPKCS5v20(block_cipher.clone(),
                                    new HMAC(hash_function.clone()),
                                    passphrase,
                                    dur,
                                    rng);
    }
    
    throw new AlgorithmNotFound(algo_spec);
}


/**
* Factory function for PBEs.
* @param pbe_oid = the oid of the desired PBE
* @param params = a DataSource providing the DER encoded parameters to use
* @param passphrase = the passphrase to use for decryption
* @return pointer to the PBE with the specified parameters
*/
PBE getPbe(in OID pbe_oid, in Vector!ubyte params, in string passphrase)
{
    SCANToken request = SCANToken(OIDS.lookup(pbe_oid));
    
    const string pbe = request.algo_name;
    
    static if (BOTAN_HAS_PBE_PKCS_V20) {
        if (pbe == "PBE-PKCS5v20")
            return new PBEPKCS5v20(params, passphrase);
    }
    
    throw new AlgorithmNotFound(pbe_oid.toString());
}