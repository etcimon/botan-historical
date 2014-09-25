/*
* PK Operation Types
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_PK_OPERATIONS_H__

#include <botan/secmem.h>
#include <botan/rng.h>
namespace PK_Ops {

/**
* Public key encryption interface
*/
class Encryption
{
	public:
		abstract size_t max_input_bits() const = 0;

		abstract SafeArray!byte encrypt(const byte msg[], size_t msg_len,
													  RandomNumberGenerator& rng) = 0;

		abstract ~Encryption() {}
};

/**
* Public key decryption interface
*/
class Decryption
{
	public:
		abstract size_t max_input_bits() const = 0;

		abstract SafeArray!byte decrypt(const byte msg[],
													  size_t msg_len) = 0;

		abstract ~Decryption() {}
};

/**
* Public key signature creation interface
*/
class Signature
{
	public:
		/**
		* Find out the number of message parts supported by this scheme.
		* @return number of message parts
		*/
		abstract size_t message_parts() const { return 1; }

		/**
		* Find out the message part size supported by this scheme/key.
		* @return size of the message parts
		*/
		abstract size_t message_part_size() const { return 0; }

		/**
		* Get the maximum message size in bits supported by this public key.
		* @return maximum message in bits
		*/
		abstract size_t max_input_bits() const = 0;

		/*
		* Perform a signature operation
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @param rng a random number generator
		*/
		abstract SafeArray!byte sign(const byte msg[], size_t msg_len,
												  RandomNumberGenerator& rng) = 0;

		abstract ~Signature() {}
};

/**
* Public key signature verification interface
*/
class Verification
{
	public:
		/**
		* Get the maximum message size in bits supported by this public key.
		* @return maximum message in bits
		*/
		abstract size_t max_input_bits() const = 0;

		/**
		* Find out the number of message parts supported by this scheme.
		* @return number of message parts
		*/
		abstract size_t message_parts() const { return 1; }

		/**
		* Find out the message part size supported by this scheme/key.
		* @return size of the message parts
		*/
		abstract size_t message_part_size() const { return 0; }

		/**
		* @return boolean specifying if this key type supports message
		* recovery and thus if you need to call verify() or verify_mr()
		*/
		abstract bool with_recovery() const = 0;

		/*
		* Perform a signature check operation
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @param sig the signature
		* @param sig_len the length of sig in bytes
		* @returns if signature is a valid one for message
		*/
		abstract bool verify(const byte[], size_t,
								  const byte[], size_t)
		{
			throw Invalid_State("Message recovery required");
		}

		/*
		* Perform a signature operation (with message recovery)
		* Only call this if with_recovery() returns true
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @returns recovered message
		*/
		abstract SafeArray!byte verify_mr(const byte[],
														 size_t)
		{
			throw Invalid_State("Message recovery not supported");
		}

		abstract ~Verification() {}
};

/**
* A generic key agreement Operation (eg DH or ECDH)
*/
class Key_Agreement
{
	public:
		/*
		* Perform a key agreement operation
		* @param w the other key value
		* @param w_len the length of w in bytes
		* @returns the agreed key
		*/
		abstract SafeArray!byte agree(const byte w[], size_t w_len) = 0;

		abstract ~Key_Agreement() {}
};

}