/*
* DESX
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_DESX_H__

#include <botan/des.h>
/**
* DESX
*/
class DESX : public Block_Cipher_Fixed_Params<8, 24>
{
	public:
		void encrypt_n(const byte in[], byte out[], size_t blocks) const;
		void decrypt_n(const byte in[], byte out[], size_t blocks) const;

		void clear();
		string name() const { return "DESX"; }
		BlockCipher* clone() const { return new DESX; }
	private:
		void key_schedule(const byte[], size_t);
		SafeArray!byte K1, K2;
		DES des;
};