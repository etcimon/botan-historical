/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.rc5;

import botan.loadstor;
import botan.rotate;
import botan.parsing;
import std.algorithm;
import botan.block.block_cipher;

/**
* RC5
*/
class RC5 : Block_Cipher_Fixed_Params!(8, 1, 32)
{
public:
	/*
	* RC5 Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			
			A += S[0]; B += S[1];
			for (size_t j = 0; j != rounds; j += 4)
			{
				A = rotate_left(A ^ B, B % 32) + S[2*j+2];
				B = rotate_left(B ^ A, A % 32) + S[2*j+3];
				
				A = rotate_left(A ^ B, B % 32) + S[2*j+4];
				B = rotate_left(B ^ A, A % 32) + S[2*j+5];
				
				A = rotate_left(A ^ B, B % 32) + S[2*j+6];
				B = rotate_left(B ^ A, A % 32) + S[2*j+7];
				
				A = rotate_left(A ^ B, B % 32) + S[2*j+8];
				B = rotate_left(B ^ A, A % 32) + S[2*j+9];
			}
			
			store_le(output, A, B);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/*
	* RC5 Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			
			for (size_t j = rounds; j != 0; j -= 4)
			{
				B = rotate_right(B - S[2*j+1], A % 32) ^ A;
				A = rotate_right(A - S[2*j  ], B % 32) ^ B;
				
				B = rotate_right(B - S[2*j-1], A % 32) ^ A;
				A = rotate_right(A - S[2*j-2], B % 32) ^ B;
				
				B = rotate_right(B - S[2*j-3], A % 32) ^ A;
				A = rotate_right(A - S[2*j-4], B % 32) ^ B;
				
				B = rotate_right(B - S[2*j-5], A % 32) ^ A;
				A = rotate_right(A - S[2*j-6], B % 32) ^ B;
			}
			B -= S[1]; A -= S[0];
			
			store_le(output, A, B);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	void clear()
	{
		zap(S);
	}

	/*
	* Return the name of this type
	*/
	string name() const
	{
		return "RC5(" ~ std.conv.to!string(rounds) ~ ")";
	}

	BlockCipher clone() const { return new RC5(rounds); }

	/**
	* RC5 Constructor
	* @param rounds the number of RC5 rounds to run. Must be between
	* 8 and 32 and a multiple of 4.
	*/
	this(size_t r)
	{
		rounds = r;
		if (rounds < 8 || rounds > 32 || (rounds % 4 != 0))
			throw new Invalid_Argument("RC5: Invalid number of rounds " ~
			                           std.conv.to!string(rounds));
	}
private:

	/*
	* RC5 Key Schedule
	*/
	void key_schedule(in ubyte* key)
	{
		S.resize(2*rounds + 2);
		
		const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
		const size_t MIX_ROUNDS	  = 3 * std.algorithm.max(WORD_KEYLENGTH, S.size());
		
		S[0] = 0xB7E15163;
		for (size_t i = 1; i != S.size(); ++i)
			S[i] = S[i-1] + 0x9E3779B9;
		
		SafeVector!uint K = SafeVector!uint(8);
		
		for (int i = length-1; i >= 0; --i)
			K[i/4] = (K[i/4] << 8) + key[i];
		
		uint A = 0, B = 0;
		
		for (size_t i = 0; i != MIX_ROUNDS; ++i)
		{
			A = rotate_left(S[i % S.size()] + A + B, 3);
			B = rotate_left(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
			S[i % S.size()] = A;
			K[i % WORD_KEYLENGTH] = B;
		}
	}


	size_t rounds;
	SafeVector!uint S;
};