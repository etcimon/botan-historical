/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.tea;
import botan.block.block_cipher;
import botan.utils.loadstor;
/**
* TEA
*/
class TEA : Block_Cipher_Fixed_Params!(8, 16)
{
public:
	/*
	* TEA Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint L = load_be!uint(input, 0);
			uint R = load_be!uint(input, 1);
			
			uint S = 0;
			for (size_t j = 0; j != 32; ++j)
			{
				S += 0x9E3779B9;
				L += ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
				R += ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
			}
			
			store_be(output, L, R);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	/*
	* TEA Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint L = load_be!uint(input, 0);
			uint R = load_be!uint(input, 1);
			
			uint S = 0xC6EF3720;
			for (size_t j = 0; j != 32; ++j)
			{
				R -= ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
				L -= ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
				S -= 0x9E3779B9;
			}
			
			store_be(output, L, R);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	void clear()
	{
		zap(K);
	}

	string name() const { return "TEA"; }
	BlockCipher clone() const { return new TEA; }
private:
	/*
	* TEA Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		K.resize(4);
		for (size_t i = 0; i != 4; ++i)
			K[i] = load_be!uint(key, i);
	}
	SafeVector!uint K;
};