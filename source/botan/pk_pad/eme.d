/*
* EME Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.eme;

import botan.utils.memory.zeroize;
import botan.rng.rng;
/**
* Encoding Method for Encryption
*/
class EME
{
public:
    /**
    * Return the maximum input size in bytes we can support
    * @param keybits = the size of the key in bits
    * @return upper bound of input in bytes
    */
    abstract size_t maximum_input_size(size_t keybits) const;

    /**
    * Encode an input
    * @param msg = the plaintext
    * @param msg_len = length of plaintext in bytes
    * @param key_bits = length of the key in bits
    * @param rng = a random number generator
    * @return encoded plaintext
    */
    final Secure_Vector!ubyte encode(in ubyte* msg, size_t msg_len,
                            size_t key_bits,
                            RandomNumberGenerator rng) const
    {
        return pad(msg, msg_len, key_bits, rng);
    }

    /**
    * Encode an input
    * @param msg = the plaintext
    * @param key_bits = length of the key in bits
    * @param rng = a random number generator
    * @return encoded plaintext
    */
    final Secure_Vector!ubyte encode(in Secure_Vector!ubyte msg, size_t key_bits, RandomNumberGenerator rng) const
    {
        return pad(msg.ptr, msg.length, key_bits, rng);
    }

    /**
    * Decode an input
    * @param msg = the encoded plaintext
    * @param msg_len = length of encoded plaintext in bytes
    * @param key_bits = length of the key in bits
    * @return plaintext
    */
    final Secure_Vector!ubyte decode(in ubyte* msg, size_t msg_len, size_t key_bits) const
    {
        return unpad(msg, msg_len, key_bits);
    }


    /**
    * Decode an input
    * @param msg = the encoded plaintext
    * @param key_bits = length of the key in bits
    * @return plaintext
    */
    final Secure_Vector!ubyte decode(in Secure_Vector!ubyte msg, size_t key_bits) const
    {
        return unpad(msg.ptr, msg.length, key_bits);
    }

    ~this() {}
private:
    /**
    * Encode an input
    * @param input = the plaintext
    * @param in_length = length of plaintext in bytes
    * @param key_length = length of the key in bits
    * @param rng = a random number generator
    * @return encoded plaintext
    */
    abstract Secure_Vector!ubyte pad(in ubyte* input,
                                     size_t in_length,
                                     size_t key_length,
                                     RandomNumberGenerator rng) const;

    /**
    * Decode an input
    * @param input = the encoded plaintext
    * @param in_length = length of encoded plaintext in bytes
    * @param key_length = length of the key in bits
    * @return plaintext
    */
    abstract Secure_Vector!ubyte unpad(in ubyte* input, size_t in_length, size_t key_length) const;
}
