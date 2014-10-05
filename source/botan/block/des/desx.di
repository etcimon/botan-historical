/*
* DESX
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.des;
/**
* DESX
*/
class DESX : public Block_Cipher_Fixed_Params!(8, 24)
{
	public:
		void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void clear();
		string name() const { return "DESX"; }
		BlockCipher clone() const { return new DESX; }
	private:
		void key_schedule(in ubyte*, size_t);
		SafeVector!ubyte K1, K2;
		DES des;
};