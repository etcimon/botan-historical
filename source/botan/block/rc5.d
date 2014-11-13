/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.rc5;

import botan.constants;
static if (BOTAN_HAS_RC5):

import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.parsing;
import std.algorithm;
import botan.block.block_cipher;

/**
* RC5
*/
final class RC5 : Block_Cipher_Fixed_Params!(8, 1, 32)
{
public:
	/*
	* RC5 Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		foreach (size_t i; 0 .. blocks)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			
			A += m_S[0]; B += m_S[1];
			for (size_t j = 0; j != m_rounds; j += 4)
			{
				A = rotate_left(A ^ B, B % 32) + m_S[2*j+2];
				B = rotate_left(B ^ A, A % 32) + m_S[2*j+3];
				
				A = rotate_left(A ^ B, B % 32) + m_S[2*j+4];
				B = rotate_left(B ^ A, A % 32) + m_S[2*j+5];
				
				A = rotate_left(A ^ B, B % 32) + m_S[2*j+6];
				B = rotate_left(B ^ A, A % 32) + m_S[2*j+7];
				
				A = rotate_left(A ^ B, B % 32) + m_S[2*j+8];
				B = rotate_left(B ^ A, A % 32) + m_S[2*j+9];
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
		foreach (size_t i; 0 .. blocks)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			
			for (size_t j = m_rounds; j != 0; j -= 4)
			{
				B = rotate_right(B - m_S[2*j+1], A % 32) ^ A;
				A = rotate_right(A - m_S[2*j  ], B % 32) ^ B;
				
				B = rotate_right(B - m_S[2*j-1], A % 32) ^ A;
				A = rotate_right(A - m_S[2*j-2], B % 32) ^ B;
				
				B = rotate_right(B - m_S[2*j-3], A % 32) ^ A;
				A = rotate_right(A - m_S[2*j-4], B % 32) ^ B;
				
				B = rotate_right(B - m_S[2*j-5], A % 32) ^ A;
				A = rotate_right(A - m_S[2*j-6], B % 32) ^ B;
			}
			B -= m_S[1]; A -= m_S[0];
			
			store_le(output, A, B);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	void clear()
	{
		zap(m_S);
	}

	/*
	* Return the name of this type
	*/
	override @property string name() const
	{
		return "RC5(" ~ to!string(m_rounds) ~ ")";
	}

	BlockCipher clone() const { return new RC5(m_rounds); }

	/**
	* RC5 Constructor
	* @param rounds the number of RC5 rounds to run. Must be between
	* 8 and 32 and a multiple of 4.
	*/
	this(size_t r)
	{
		m_rounds = r;
		if (m_rounds < 8 || m_rounds > 32 || (m_rounds % 4 != 0))
			throw new Invalid_Argument("RC5: Invalid number of rounds " ~
			                           to!string(m_rounds));
	}
private:

	/*
	* RC5 Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		m_S.resize(2*m_rounds + 2);
		
		const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
		const size_t MIX_ROUNDS	  = 3 * std.algorithm.max(WORD_KEYLENGTH, m_S.length);
		
		m_S[0] = 0xB7E15163;
		foreach (size_t i; 1 .. m_S.length)
			m_S[i] = m_S[i-1] + 0x9E3779B9;
		
		Secure_Vector!uint K = Secure_Vector!uint(8);
		
		for (int i = length-1; i >= 0; --i)
			K[i/4] = (K[i/4] << 8) + key[i];
		
		uint A = 0, B = 0;
		
		foreach (size_t i; 0 .. MIX_ROUNDS)
		{
			A = rotate_left(m_S[i % m_S.length] + A + B, 3);
			B = rotate_left(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
			m_S[i % m_S.length] = A;
			K[i % WORD_KEYLENGTH] = B;
		}
	}


	size_t m_rounds;
	Secure_Vector!uint m_S;
}