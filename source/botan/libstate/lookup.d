/*
* Algorithm Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.lookup;

public import botan.filters.filters;
public import botan.modes.mode_pad;
public import botan.kdf.kdf;
public import botan.pk_pad.eme;
public import botan.pk_pad.emsa;
public import botan.pbkdf.pbkdf;
public import botan.engine.engine;
import botan.libstate.libstate;

/**
* Retrieve an object prototype from the global factory
* @param algo_spec = an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
const(BlockCipher) retrieveBlockCipher(in string algo_spec)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    return af.prototypeBlockCipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec = an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
const(StreamCipher) retrieveStreamCipher(in string algo_spec)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    return af.prototypeStreamCipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec = an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
const(HashFunction) retrieveHash(in string algo_spec)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    return af.prototypeHashFunction(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec = an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
const(MessageAuthenticationCode) retrieveMac(in string algo_spec)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    return af.prototypeMac(algo_spec);
}

/**
* Password based key derivation function factory method
* @param algo_spec = the name of the desired PBKDF algorithm
* @return pointer to newly allocated object of that type
*/
PBKDF getPbkdf(in string algo_spec)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    if (PBKDF pbkdf = af.makePbkdf(algo_spec))
        return pbkdf;
    
    throw new AlgorithmNotFound(algo_spec);
}

/**
* Get a cipher object.
* Factory method for general symmetric cipher filters.
* @param algo_spec = the name of the desired cipher
* @param key = the key to be used for encryption/decryption performed by
* the filter
* @param iv = the initialization vector to be used
* @param direction = determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to newly allocated encryption or decryption filter
*/
KeyedFilter getCipher(in string algo_spec, in SymmetricKey key, in InitializationVector iv, CipherDir direction)
{
    KeyedFilter cipher = getCipher(algo_spec, direction);
    cipher.setKey(key);
    
    if (iv.length)
        cipher.setIv(iv);
    
    return cipher;
}

/**
* Factory method for general symmetric cipher filters.
* @param algo_spec = the name of the desired cipher
* @param key = the key to be used for encryption/decryption performed by
* the filter
* @param direction = determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to the encryption or decryption filter
*/
KeyedFilter getCipher(in string algo_spec, in SymmetricKey key, CipherDir direction)
{
    return getCipher(algo_spec, key, InitializationVector(), direction);
}


/**
* Factory method for general symmetric cipher filters. No key will be
* set in the filter.
*
* @param algo_spec = the name of the desired cipher
* @param direction = determines whether the filter will be an encrypting or
* decrypting filter
* @return pointer to the encryption or decryption filter
*/
KeyedFilter getCipher(in string algo_spec, CipherDir direction)
{
    AlgorithmFactory af = globalState().algorithmFactory();

    foreach (Engine engine; af.engines[]) {
        if (KeyedFilter algo = engine.getCipher(algo_spec, direction, af))
            return algo;
    }
    
    throw new AlgorithmNotFound(algo_spec);
}

/**
* Check if an algorithm exists.
* @param algo_spec = the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
bool haveAlgorithm(in string name)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    if (af.prototypeBlockCipher(name))
        return true;
    if (af.prototypeStreamCipher(name))
        return true;
    if (af.prototypeHashFunction(name))
        return true;
    if (af.prototypeMac(name))
        return true;
    return false;
}