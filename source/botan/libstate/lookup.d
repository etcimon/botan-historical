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
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
BlockCipher retrieve_block_cipher(in string algo_spec) const
{
    Algorithm_Factory af = global_state().algorithm_factory();
    return af.prototype_block_cipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
StreamCipher retrieve_stream_cipher(in string algo_spec) const
{
    Algorithm_Factory af = global_state().algorithm_factory();
    return af.prototype_stream_cipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
HashFunction retrieve_hash(in string algo_spec) const
{
    Algorithm_Factory af = global_state().algorithm_factory();
    return af.prototype_hash_function(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
             library retains ownership
*/
MessageAuthenticationCode retrieve_mac(in string algo_spec) const
{
    Algorithm_Factory af = global_state().algorithm_factory();
    return af.prototype_mac(algo_spec);
}

/**
* Password based key derivation function factory method
* @param algo_spec the name of the desired PBKDF algorithm
* @return pointer to newly allocated object of that type
*/
PBKDF get_pbkdf(in string algo_spec)
{
    Algorithm_Factory af = global_state().algorithm_factory();
    
    if (PBKDF pbkdf = af.make_pbkdf(algo_spec))
        return pbkdf;
    
    throw new Algorithm_Not_Found(algo_spec);
}

/**
* Get a cipher object.
* Factory method for general symmetric cipher filters.
* @param algo_spec the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param iv the initialization vector to be used
* @param direction determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to newly allocated encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec, in SymmetricKey key, in InitializationVector iv, Cipher_Dir direction)
{
    Keyed_Filter cipher = get_cipher(algo_spec, direction);
    cipher.set_key(key);
    
    if (iv.length)
        cipher.set_iv(iv);
    
    return cipher;
}

/**
* Factory method for general symmetric cipher filters.
* @param algo_spec the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param direction determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to the encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec, in SymmetricKey key, Cipher_Dir direction)
{
    return get_cipher(algo_spec, key, InitializationVector(), direction);
}


/**
* Factory method for general symmetric cipher filters. No key will be
* set in the filter.
*
* @param algo_spec the name of the desired cipher
* @param direction determines whether the filter will be an encrypting or
* decrypting filter
* @return pointer to the encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec, Cipher_Dir direction)
{
    Algorithm_Factory af = global_state().algorithm_factory();

    foreach (Engine engine; af.engines) {
        if (Keyed_Filter algo = engine.get_cipher(algo_spec, direction, af))
            return algo;
    }
    
    throw new Algorithm_Not_Found(algo_spec);
}

/**
* Check if an algorithm exists.
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
bool have_algorithm(in string name)
{
    Algorithm_Factory af = global_state().algorithm_factory();
    
    if (af.prototype_block_cipher(name))
        return true;
    if (af.prototype_stream_cipher(name))
        return true;
    if (af.prototype_hash_function(name))
        return true;
    if (af.prototype_mac(name))
        return true;
    return false;
}