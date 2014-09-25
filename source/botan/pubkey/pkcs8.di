/*
* PKCS #8
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/x509_key.h>
#include <functional>
#include <chrono>
/**
* PKCS #8 General Exception
*/
struct PKCS8_Exception : public Decoding_Error
{
	PKCS8_Exception(in string error) :
		Decoding_Error("PKCS #8: " + error) {}
};

/**
* This namespace contains functions for handling PKCS #8 private keys
*/
namespace PKCS8 {

/**
* BER encode a private key
* @param key the private key to encode
* @return BER encoded key
*/
SafeArray!byte BER_encode(in Private_Key key);

/**
* Get a string containing a PEM encoded private key.
* @param key the key to encode
* @return encoded key
*/
string PEM_encode(in Private_Key key);

/**
* Encrypt a key using PKCS #8 encryption
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param msec number of milliseconds to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
			algorithm; if empty ("") a reasonable (portable/secure)
			default will be chosen.
* @return encrypted key in binary BER form
*/
std::vector<byte>
BER_encode(in Private_Key key,
			  RandomNumberGenerator& rng,
			  in string pass,
			  std::chrono::milliseconds msec = std::chrono::milliseconds(300),
			  in string pbe_algo = "");

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param msec number of milliseconds to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
			algorithm; if empty ("") a reasonable (portable/secure)
			default will be chosen.
* @return encrypted key in PEM form
*/
string
PEM_encode(in Private_Key key,
			  RandomNumberGenerator rng,
			  in string pass,
			  std::chrono::milliseconds msec = std::chrono::milliseconds(300),
			  in string pbe_algo = "");

/**
* Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
Private_Key* load_key(
  DataSource& source,
  RandomNumberGenerator& rng,
  Tuple!(bool, string) delegate() get_passphrase);

/** Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
Private_Key* load_key(DataSource& source,
										  RandomNumberGenerator& rng,
										  in string pass = "");

/**
* Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
Private_Key* load_key(
  in string filename,
  RandomNumberGenerator& rng,
  Tuple!(bool, string) delegate() get_passphrase);

/** Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
Private_Key* load_key(in string filename,
										  RandomNumberGenerator& rng,
										  in string pass = "");

/**
* Copy an existing encoded key object.
* @param key the key to copy
* @param rng the rng to use
* @return new copy of the key
*/
Private_Key* copy_key(in Private_Key key,
										  RandomNumberGenerator& rng);

}