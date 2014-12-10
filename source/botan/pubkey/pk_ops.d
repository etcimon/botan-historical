/*
* PK Operation Types
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pk_ops;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.alg_id;
public import botan.rng.rng;
public import botan.pubkey.pk_keys;
import botan.utils.memory.zeroize;

/**
* Public key encryption interface
*/
interface Encryption
{
public:
    abstract size_t maxInputBits() const;

    abstract SecureVector!ubyte encrypt(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng);

}

/**
* Public key decryption interface
*/
interface Decryption
{
public:
    abstract size_t maxInputBits() const;

    abstract SecureVector!ubyte decrypt(in ubyte* msg, size_t msg_len);

}

/**
* Public key signature creation interface
*/
interface Signature
{
public:
    /**
    * Find out the number of message parts supported by this scheme.
    * @return number of message parts
    */
    abstract size_t messageParts() const;

    /**
    * Find out the message part size supported by this scheme/key.
    * @return size of the message parts
    */
    abstract size_t messagePartSize() const;

    /**
    * Get the maximum message size in bits supported by this public key.
    * @return maximum message in bits
    */
    abstract size_t maxInputBits() const;

    /*
    * Perform a signature operation
    * @param msg = the message
    * @param msg_len = the length of msg in bytes
    * @param rng = a random number generator
    */
    abstract SecureVector!ubyte sign(in ubyte* msg, size_t msg_len, RandomNumberGenerator rng);

}

/**
* Public key signature verification interface
*/
interface Verification
{
public:
    /**
    * Get the maximum message size in bits supported by this public key.
    * @return maximum message in bits
    */
    abstract size_t maxInputBits() const;

    /**
    * Find out the number of message parts supported by this scheme.
    * @return number of message parts
    */
    abstract size_t messageParts() const;

    /**
    * Find out the message part size supported by this scheme/key.
    * @return size of the message parts
    */
    abstract size_t messagePartSize() const;

    /**
    * @return boolean specifying if this key type supports message
    * recovery and thus if you need to call verify() or verifyMr()
    */
    abstract bool withRecovery() const;

    /*
    * Perform a signature check operation
    * @param msg = the message
    * @param msg_len = the length of msg in bytes
    * @param sig = the signature
    * @param sig_len = the length of sig in bytes
    * @returns if signature is a valid one for message
    */
    abstract bool verify(const ubyte*, size_t, const ubyte*, size_t);

    /*
    * Perform a signature operation (with message recovery)
    * Only call this if withRecovery() returns true
    * @param msg = the message
    * @param msg_len = the length of msg in bytes
    * @returns recovered message
    */
    abstract SecureVector!ubyte verifyMr(const ubyte*, size_t);

}

/**
* A generic key agreement Operation (eg DH or ECDH)
*/
interface KeyAgreement
{
public:
    /*
    * Perform a key agreement operation
    * @param w = the other key value
    * @param w_len = the length of w in bytes
    * @returns the agreed key
    */
    abstract SecureVector!ubyte agree(in ubyte* w, size_t w_len);
}