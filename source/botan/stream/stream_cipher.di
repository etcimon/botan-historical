/*
* Stream Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_base.sym_algo;
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
		void cipher1(ubyte buf[], size_t len)
		{ cipher(buf, buf, len); }

		void encipher(Alloc)(Vector!( ubyte, Alloc )& inoutput)
		{ cipher(&inoutput[0], &inoutput[0], inoutput.size()); }

		void encrypt(Alloc)(Vector!( ubyte, Alloc )& inoutput)
		{ cipher(&inoutput[0], &inoutput[0], inoutput.size()); }

		void decrypt(Alloc)(Vector!( ubyte, Alloc )& inoutput)
		{ cipher(&inoutput[0], &inoutput[0], inoutput.size()); }

		/**
		* Resync the cipher using the IV
		* @param iv the initialization vector
		* @param iv_len the length of the IV in bytes
		*/
		abstract void set_iv(in ubyte* iv, size_t iv_len);

		/**
		* @param iv_len the length of the IV in bytes
		* @return if the length is valid for this algorithm
		*/
		abstract bool valid_iv_length(size_t iv_len) const;

		/**
		* Get a new object representing the same algorithm as *this
		*/
		abstract StreamCipher clone() const;
};