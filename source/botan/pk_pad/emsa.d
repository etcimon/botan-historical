/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.rng.rng;
/**
* Encoding Method for Signatures, Appendix
*/
class EMSA
{
public:
	/**
	* Add more data to the signature computation
	* @param input some data
	* @param length length of input in bytes
	*/
	abstract void update(in ubyte* input, size_t length);

	/**
	* @return raw hash
	*/
	abstract SafeVector!ubyte raw_data();

	/**
	* Return the encoding of a message
	* @param msg the result of raw_data()
	* @param output_bits the desired output bit size
	* @param rng a random number generator
	* @return encoded signature
	*/
	abstract SafeVector!ubyte encoding_of(in SafeVector!ubyte msg,
														size_t output_bits,
														RandomNumberGenerator rng);

	/**
	* Verify the encoding
	* @param coded the received (coded) message representative
	* @param raw the computed (local, uncoded) message representative
	* @param key_bits the size of the key in bits
	* @return true if coded is a valid encoding of raw, otherwise false
	*/
	abstract bool verify(in SafeVector!ubyte coded,
							  in SafeVector!ubyte raw,
							  size_t key_bits);
	~this() {}
};

/**
* Factory method for EMSA (message-encoding methods for signatures
* with appendix) objects
* @param algo_spec the name of the EME to create
* @return pointer to newly allocated object of that type
*/
EMSA* get_emsa(in string algo_spec);