/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.rc6;

import botan.constants;
static if (BOTAN_HAS_RC6):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import std.algorithm;

/**
* RC6, Ron Rivest's AES candidate
*/
final class RC6 : Block_Cipher_Fixed_Params!(16, 1, 32)
{
public:
	/*
	* RC6 Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			uint C = load_le!uint(input, 2);
			uint D = load_le!uint(input, 3);
			
			B += m_S[0]; D += m_S[1];
			
			for (size_t j = 0; j != 20; j += 4)
			{
				uint T1, T2;
				
				T1 = rotate_left(B*(2*B+1), 5);
				T2 = rotate_left(D*(2*D+1), 5);
				A = rotate_left(A ^ T1, T2 % 32) + m_S[2*j+2];
				C = rotate_left(C ^ T2, T1 % 32) + m_S[2*j+3];
				
				T1 = rotate_left(C*(2*C+1), 5);
				T2 = rotate_left(A*(2*A+1), 5);
				B = rotate_left(B ^ T1, T2 % 32) + m_S[2*j+4];
				D = rotate_left(D ^ T2, T1 % 32) + m_S[2*j+5];
				
				T1 = rotate_left(D*(2*D+1), 5);
				T2 = rotate_left(B*(2*B+1), 5);
				C = rotate_left(C ^ T1, T2 % 32) + m_S[2*j+6];
				A = rotate_left(A ^ T2, T1 % 32) + m_S[2*j+7];
				
				T1 = rotate_left(A*(2*A+1), 5);
				T2 = rotate_left(C*(2*C+1), 5);
				D = rotate_left(D ^ T1, T2 % 32) + m_S[2*j+8];
				B = rotate_left(B ^ T2, T1 % 32) + m_S[2*j+9];
			}
			
			A += m_S[42]; C += m_S[43];
			
			store_le(output, A, B, C, D);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	/*
	* RC6 Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint A = load_le!uint(input, 0);
			uint B = load_le!uint(input, 1);
			uint C = load_le!uint(input, 2);
			uint D = load_le!uint(input, 3);
			
			C -= m_S[43]; A -= m_S[42];
			
			for (size_t j = 0; j != 20; j += 4)
			{
				uint T1, T2;
				
				T1 = rotate_left(A*(2*A+1), 5);
				T2 = rotate_left(C*(2*C+1), 5);
				B = rotate_right(B - S[41 - 2*j], T1 % 32) ^ T2;
				D = rotate_right(D - S[40 - 2*j], T2 % 32) ^ T1;
				
				T1 = rotate_left(D*(2*D+1), 5);
				T2 = rotate_left(B*(2*B+1), 5);
				A = rotate_right(A - m_S[39 - 2*j], T1 % 32) ^ T2;
				C = rotate_right(C - m_S[38 - 2*j], T2 % 32) ^ T1;
				
				T1 = rotate_left(C*(2*C+1), 5);
				T2 = rotate_left(A*(2*A+1), 5);
				D = rotate_right(D - m_S[37 - 2*j], T1 % 32) ^ T2;
				B = rotate_right(B - m_S[36 - 2*j], T2 % 32) ^ T1;
				
				T1 = rotate_left(B*(2*B+1), 5);
				T2 = rotate_left(D*(2*D+1), 5);
				C = rotate_right(C - m_S[35 - 2*j], T1 % 32) ^ T2;
				A = rotate_right(A - m_S[34 - 2*j], T2 % 32) ^ T1;
			}
			
			D -= m_S[1]; B -= m_S[0];
			
			store_le(output, A, B, C, D);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	void clear()
	{
		zap(m_S);
	}

	override @property string name() const { return "RC6"; }
	BlockCipher clone() const { return new RC6; }
private:
	/*
	* RC6 Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		m_S.resize(44);
		
		const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
		const size_t MIX_ROUNDS	  = 3 * std.algorithm.max(WORD_KEYLENGTH, m_S.length);
		
		m_S[0] = 0xB7E15163;
		for (size_t i = 1; i != S.length; ++i)
			m_S[i] = m_S[i-1] + 0x9E3779B9;
		
		Secure_Vector!uint K = Secure_Vector!uint(8);
		
		for (int i = length-1; i >= 0; --i)
			K[i/4] = (K[i/4] << 8) + key[i];
		
		uint A = 0, B = 0;
		for (size_t i = 0; i != MIX_ROUNDS; ++i)
		{
			A = rotate_left(m_S[i % m_S.length] + A + B, 3);
			B = rotate_left(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
			m_S[i % m_S.length] = A;
			K[i % WORD_KEYLENGTH] = B;
		}
	}

	Secure_Vector!uint m_S;
}