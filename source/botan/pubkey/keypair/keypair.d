/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.keypair;
import botan.pubkey;
namespace KeyPair {

/*
* Check an encryption key pair for consistency
*/
bool encryption_consistency_check(RandomNumberGenerator rng,
											 in Private_Key key,
											 in string padding)
{
	PK_Encryptor_EME encryptor(key, padding);
	PK_Decryptor_EME decryptor(key, padding);

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

/*
* Check a signature key pair for consistency
*/
bool signature_consistency_check(RandomNumberGenerator rng,
											in Private_Key key,
											in string padding)
{
	PK_Signer signer(key, padding);
	PK_Verifier verifier = new PK_Verifier(key, padding);
		scope(exit) delete verifier;
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

}

}
