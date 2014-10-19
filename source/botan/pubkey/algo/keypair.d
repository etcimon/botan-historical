/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.keypair;

import botan.pk_keys;
import botan.pubkey.pubkey;

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param key the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
bool encryption_consistency_check(RandomNumberGenerator rng,
                                  in Private_Key key,
                                  in string padding)
{
	PK_Encryptor_EME encryptor = new PK_Encryptor_EME(key, padding);
	PK_Decryptor_EME decryptor = new PK_Decryptor_EME(key, padding);
	scope(exit) { delete encryptor; delete decryptor; }
	
	/*
	Weird corner case, if the key is too small to encrypt anything at
	all. This can happen with very small RSA keys with PSS
	*/
	if (encryptor.maximum_input_size() == 0)
		return true;
	
	Vector!ubyte plaintext =
		unlock(rng.random_vec(encryptor.maximum_input_size() - 1));
	
	Vector!ubyte ciphertext = encryptor.encrypt(plaintext, rng);
	if (ciphertext == plaintext)
		return false;
	
	Vector!ubyte decrypted = unlock(decryptor.decrypt(ciphertext));
	
	return (plaintext == decrypted);
}

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param key the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
bool signature_consistency_check(RandomNumberGenerator rng,
                                 in Private_Key key,
                                 in string padding)
{
	PK_Signer signer = PK_Signer(key, padding);
	PK_Verifier verifier = PK_Verifier(key, padding);
	Vector!ubyte message = unlock(rng.random_vec(16));
	
	Vector!ubyte signature;
	
	try
	{
		signature = signer.sign_message(message, rng);
	}
	catch(Encoding_Error)
	{
		return false;
	}
	
	if (!verifier.verify_message(message, signature))
		return false;
	
	// Now try to check a corrupt signature, ensure it does not succeed
	++message[0];
	
	if (verifier.verify_message(message, signature))
		return false;
	
	return true;
}
