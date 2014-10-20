/*
* PK Operation Types
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pk_ops;

import botan.alloc.secmem;
import botan.rng.rng;

/**
* Public key encryption interface
*/
class Encryption
{
	public:
		abstract size_t max_input_bits() const;

		abstract SafeVector!ubyte encrypt(in ubyte* msg, size_t msg_len,
													  RandomNumberGenerator rng);

		~this() {}
};

/**
* Public key decryption interface
*/
class Decryption
{
	public:
		abstract size_t max_input_bits() const;

		abstract SafeVector!ubyte decrypt(in ubyte* msg,
													  size_t msg_len);

		~this() {}
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
		abstract size_t max_input_bits() const;

		/*
		* Perform a signature operation
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @param rng a random number generator
		*/
		abstract SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
												  RandomNumberGenerator rng);

		~this() {}
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
		abstract size_t max_input_bits() const;

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
		abstract bool with_recovery() const;

		/*
		* Perform a signature check operation
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @param sig the signature
		* @param sig_len the length of sig in bytes
		* @returns if signature is a valid one for message
		*/
		abstract bool verify(const ubyte[], size_t,
								  const ubyte[], size_t)
		{
			throw new Invalid_State("Message recovery required");
		}

		/*
		* Perform a signature operation (with message recovery)
		* Only call this if with_recovery() returns true
		* @param msg the message
		* @param msg_len the length of msg in bytes
		* @returns recovered message
		*/
		abstract SafeVector!ubyte verify_mr(const ubyte[],
														 size_t)
		{
			throw new Invalid_State("Message recovery not supported");
		}

		~this() {}
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
		abstract SafeVector!ubyte agree(in ubyte* w, size_t w_len);

		~this() {}
};