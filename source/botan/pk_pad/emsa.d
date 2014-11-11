/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa;

import botan.alloc.zeroize;
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
	abstract Secure_Vector!ubyte raw_data();

	/**
	* Return the encoding of a message
	* @param msg the result of raw_data()
	* @param output_bits the desired output bit size
	* @param rng a random number generator
	* @return encoded signature
	*/
	abstract Secure_Vector!ubyte encoding_of(in Secure_Vector!ubyte msg,
														size_t output_bits,
														RandomNumberGenerator rng);

	/**
	* Verify the encoding
	* @param coded the received (coded) message representative
	* @param raw the computed (local, uncoded) message representative
	* @param key_bits the size of the key in bits
	* @return true if coded is a valid encoding of raw, otherwise false
	*/
	abstract bool verify(in Secure_Vector!ubyte coded,
							  in Secure_Vector!ubyte raw,
							  size_t key_bits);
	~this() {}
}