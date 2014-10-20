/*
* Stream Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.stream_cipher;

public import botan.algo_base.sym_algo;
/**
* Base class for all stream ciphers
*/
class StreamCipher : SymmetricAlgorithm
{
public:
	/**
	* Encrypt or decrypt a message
	* @param input the plaintext
	* @param output the ubyte array to hold the output, i.e. the ciphertext
	* @param len the length of both in and out in bytes
	*/
	abstract void cipher(in ubyte* input, ubyte* output);

	/**
	* Encrypt or decrypt a message
	* @param buf the plaintext / ciphertext
	* @param len the length of buf in bytes
	*/
	void cipher1(ubyte buf*, size_t len)
	{ cipher(buf, buf, len); }

	void encipher(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(&inoutput[0], &inoutput[0], inoutput.length); }

	void encrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(&inoutput[0], &inoutput[0], inoutput.length); }

	void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
	{ cipher(&inoutput[0], &inoutput[0], inoutput.length); }

	/**
	* Resync the cipher using the IV
	* @param iv the initialization vector
	* @param iv_len the length of the IV in bytes
	*/
	abstract void set_iv(const ubyte*, size_t iv_len)
	{
		if (iv_len)
			throw new Invalid_Argument("The stream cipher " ~ name() +
			                           " does not support resyncronization");
	}

	/**
	* @param iv_len the length of the IV in bytes
	* @return if the length is valid for this algorithm
	*/
	abstract bool valid_iv_length(size_t iv_len) const
	{
		return (iv_len == 0);
	}

	/**
	* Get a new object representing the same algorithm as *this
	*/
	abstract StreamCipher clone() const;
};



