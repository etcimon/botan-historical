/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.keypair;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.pubkey.pk_keys;
public import botan.pubkey.pubkey;
import botan.utils.types;

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng = the rng to use
* @param key = the key to test
* @param padding = the encryption padding method to use
* @return true if consistent otherwise false
*/
bool encryptionConsistencyCheck(RandomNumberGenerator rng,
                                  in PrivateKey key,
                                  in string padding)
{
    auto encryptor = scoped!PKEncryptorEME(key, padding);
    auto decryptor = scoped!PKDecryptorEME(key, padding);
    
    /*
    Weird corner case, if the key is too small to encrypt anything at
    all. This can happen with very small RSA keys with PSS
    */
    if (encryptor.maximumInputSize() == 0)
        return true;
    
    Vector!ubyte plaintext = unlock(rng.randomVec(encryptor.maximumInputSize() - 1));
    
    Vector!ubyte ciphertext = encryptor.encrypt(plaintext, rng);
    if (ciphertext == plaintext)
        return false;
    
    Vector!ubyte decrypted = unlock(decryptor.decrypt(ciphertext));
    
    return (plaintext == decrypted);
}

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng = the rng to use
* @param key = the key to test
* @param padding = the signature padding method to use
* @return true if consistent otherwise false
*/
bool signatureConsistencyCheck(RandomNumberGenerator rng,
                                 in PrivateKey key,
                                 in string padding)
{
    auto signer = PKSigner(key, padding);
    auto verifier = PKVerifier(key, padding);
    Vector!ubyte message = unlock(rng.randomVec(16));
    
    Vector!ubyte signature;
    
    try
    {
        signature = signer.signMessage(message, rng);
    }
    catch(EncodingError)
    {
        return false;
    }
    
    if (!verifier.verifyMessage(message, signature))
        return false;
    
    // Now try to check a corrupt signature, ensure it does not succeed
    ++message[0];
    
    if (verifier.verifyMessage(message, signature))
        return false;
    
    return true;
}
