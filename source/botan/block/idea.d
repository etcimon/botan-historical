/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.idea;
import botan.block.block_cipher;
import botan.loadstor;

/**
* IDEA
*/
class IDEA : Block_Cipher_Fixed_Params!(8, 16)
{
public:
	/*
	* IDEA Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		idea_op(input, output, blocks, &EK[0]);
	}

	/*
	* IDEA Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		idea_op(input, output, blocks, &DK[0]);
	}

	void clear()
	{
		zap(EK);
		zap(DK);
	}

	string name() const { return "IDEA"; }
	BlockCipher clone() const { return new IDEA; }
package:
	/**
	* @return const reference to encryption subkeys
	*/
	ref const SafeVector!ushort get_EK() const { return EK; }

	/**
	* @return const reference to decryption subkeys
	*/
	ref const SafeVector!ushort get_DK() const { return DK; }

private:
	/*
	* IDEA Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		EK.resize(52);
		DK.resize(52);
		
		for (size_t i = 0; i != 8; ++i)
			EK[i] = load_be!ushort(key, i);
		
		for (size_t i = 1, j = 8, offset = 0; j != 52; i %= 8, ++i, ++j)
		{
			EK[i+7+offset] = cast(ushort)((EK[(i	  % 8) + offset] << 9) |
			                              (EK[((i+1) % 8) + offset] >> 7));
			offset += (i == 8) ? 8 : 0;
		}
		
		DK[51] = mul_inv(EK[3]);
		DK[50] = -EK[2];
		DK[49] = -EK[1];
		DK[48] = mul_inv(EK[0]);
		
		for (size_t i = 1, j = 4, counter = 47; i != 8; ++i, j += 6)
		{
			DK[counter--] = EK[j+1];
			DK[counter--] = EK[j];
			DK[counter--] = mul_inv(EK[j+5]);
			DK[counter--] = -EK[j+3];
			DK[counter--] = -EK[j+4];
			DK[counter--] = mul_inv(EK[j+2]);
		}
		
		DK[5] = EK[47];
		DK[4] = EK[46];
		DK[3] = mul_inv(EK[51]);
		DK[2] = -EK[50];
		DK[1] = -EK[49];
		DK[0] = mul_inv(EK[48]);
	}

	SafeVector!ushort EK, DK;
};

package {
	
	/*
	* Multiplication modulo 65537
	*/
	ushort mul(ushort x, ushort y)
	{
		const uint P = cast(uint)(x) * y;
		
		// P ? 0xFFFF : 0
		const ushort P_mask = !P - 1;
		
		const uint P_hi = P >> 16;
		const uint P_lo = P & 0xFFFF;
		
		const ushort r_1 = (P_lo - P_hi) + (P_lo < P_hi);
		const ushort r_2 = 1 - x - y;
		
		return (r_1 & P_mask) | (r_2 & ~P_mask);
	}
	
	/*
	* Find multiplicative inverses modulo 65537
	*
	* 65537 is prime; thus Fermat's little theorem tells us that
	* x^65537 == x modulo 65537, which means
	* x^(65537-2) == x^-1 modulo 65537 since
	* x^(65537-2) * x == 1 mod 65537
	*
	* Do the exponentiation with a basic square and multiply: all bits are
	* of exponent are 1 so we always multiply
	*/
	ushort mul_inv(ushort x)
	{
		ushort y = x;
		
		for (size_t i = 0; i != 15; ++i)
		{
			y = mul(y, y); // square
			y = mul(y, x);
		}
		
		return y;
	}
	
	/**
	* IDEA is involutional, depending only on the key schedule
	*/
	void idea_op(ubyte* input, ubyte* output, size_t blocks)
	{
		const size_t BLOCK_SIZE = 8;
		
		for (size_t i = 0; i != blocks; ++i)
		{
			ushort X1 = load_be!ushort(input, 0);
			ushort X2 = load_be!ushort(input, 1);
			ushort X3 = load_be!ushort(input, 2);
			ushort X4 = load_be!ushort(input, 3);
			
			for (size_t j = 0; j != 8; ++j)
			{
				X1 = mul(X1, K[6*j+0]);
				X2 += K[6*j+1];
				X3 += K[6*j+2];
				X4 = mul(X4, K[6*j+3]);
				
				ushort T0 = X3;
				X3 = mul(X3 ^ X1, K[6*j+4]);
				
				ushort T1 = X2;
				X2 = mul((X2 ^ X4) + X3, K[6*j+5]);
				X3 += X2;
				
				X1 ^= X2;
				X4 ^= X3;
				X2 ^= T0;
				X3 ^= T1;
			}
			
			X1  = mul(X1, K[48]);
			X2 += K[50];
			X3 += K[49];
			X4  = mul(X4, K[51]);
			
			store_be(output, X1, X3, X2, X4);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	
}