/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa;

import memutils.vector;
public import botan.rng.rng;
/**
* Encoding Method for Signatures, Appendix
*/
interface EMSA
{
public:
    /**
    * Add more data to the signature computation
    * @param input = some data
    * @param length = length of input in bytes
    */
    abstract void update(const(ubyte)* input, size_t length);

    /**
    * @return raw hash
    */
    abstract SecureVector!ubyte rawData();

    /**
    * Return the encoding of a message
    * @param msg = the result of rawData()
    * @param output_bits = the desired output bit size
    * @param rng = a random number generator
    * @return encoded signature
    */
    abstract SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng);

    /// ditto
    final SecureVector!ubyte encodingOf(const SecureVector!ubyte msg,
                                          size_t output_bits,
                                          RandomNumberGenerator rng)
    {
        return encodingOf(msg, output_bits, rng);
    }

    /**
    * Verify the encoding
    * @param coded = the received (coded) message representative
    * @param raw = the computed (local, uncoded) message representative
    * @param key_bits = the size of the key in bits
    * @return true if coded is a valid encoding of raw, otherwise false
    */
    abstract bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw,
                         size_t key_bits);
}