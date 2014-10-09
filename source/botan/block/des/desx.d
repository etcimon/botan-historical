/*
* DESX
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.des.desx;

import botan.block.des.des;
import botan.internal.xor_buf;

/**
* DESX
*/
class DESX : Block_Cipher_Fixed_Params!(8, 24)
{
public:
	/*
	* DESX Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			xor_buf(output, input, &K1[0], BLOCK_SIZE);
			des.encrypt(output);
			xor_buf(output, &K2[0], BLOCK_SIZE);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/*
	* DESX Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{	
		for (size_t i = 0; i != blocks; ++i)
		{
			xor_buf(output, input, &K2[0], BLOCK_SIZE);
			des.decrypt(output);
			xor_buf(output, &K1[0], BLOCK_SIZE);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	void clear()
	{
		des.clear();
		zap(K1);
		zap(K2);
	}

	string name() const { return "DESX"; }
	BlockCipher clone() const { return new DESX; }

private:
	/*
	* DESX Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		K1.assign(key, key + 8);
		des.set_key(key + 8, 8);
		K2.assign(key + 16, key + 24);
	}

	SafeVector!ubyte K1, K2;
	DES des;
};



