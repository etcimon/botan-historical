/*
* Noekeon in SIMD
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.noekeon_simd;

import botan.constants;
static if (BOTAN_HAS_NOEKEON_SIMD):

import botan.block.noekeon;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.simd.simd_32;

/**
* Noekeon implementation using SIMD operations
*/
final class Noekeon_SIMD : Noekeon
{
public:
	override @property size_t parallelism() const { return 4; }

	/*
	* Noekeon Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const Secure_Vector!uint EK = this.get_EK();
		
		SIMD_32 K0 = SIMD_32(EK[0]);
		SIMD_32 K1 = SIMD_32(EK[1]);
		SIMD_32 K2 = SIMD_32(EK[2]);
		SIMD_32 K3 = SIMD_32(EK[3]);
		
		while(blocks >= 4)
		{
			SIMD_32 A0 = SIMD_32.load_be(input	  );
			SIMD_32 A1 = SIMD_32.load_be(input + 16);
			SIMD_32 A2 = SIMD_32.load_be(input + 32);
			SIMD_32 A3 = SIMD_32.load_be(input + 48);
			
			SIMD_32.transpose(A0, A1, A2, A3);
			
			foreach (size_t i; 0 .. 16)
			{
				A0 ^= SIMD_32(RC[i]);
				
				mixin(NOK_SIMD_THETA());
				
				A1.rotate_left(1);
				A2.rotate_left(5);
				A3.rotate_left(2);

				mixin(NOK_SIMD_GAMMA());
				
				A1.rotate_right(1);
				A2.rotate_right(5);
				A3.rotate_right(2);
			}
			
			A0 ^= SIMD_32(RC[16]);
			mixin(NOK_SIMD_THETA());
			
			SIMD_32.transpose(A0, A1, A2, A3);
			
			A0.store_be(output);
			A1.store_be(output + 16);
			A2.store_be(output + 32);
			A3.store_be(output + 48);
			
			input += 64;
			output += 64;
			blocks -= 4;
		}
		
		if (blocks)
			super.encrypt_n(input, output, blocks);
	}

	/*
	* Noekeon Encryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const Secure_Vector!uint DK = this.get_DK();
		
		SIMD_32 K0 = SIMD_32(DK[0]);
		SIMD_32 K1 = SIMD_32(DK[1]);
		SIMD_32 K2 = SIMD_32(DK[2]);
		SIMD_32 K3 = SIMD_32(DK[3]);
		
		while(blocks >= 4)
		{
			SIMD_32 A0 = SIMD_32.load_be(input	  );
			SIMD_32 A1 = SIMD_32.load_be(input + 16);
			SIMD_32 A2 = SIMD_32.load_be(input + 32);
			SIMD_32 A3 = SIMD_32.load_be(input + 48);
			
			SIMD_32.transpose(A0, A1, A2, A3);
			
			foreach (size_t i; 0 .. 16)
			{
				mixin(NOK_SIMD_THETA());
				
				A0 ^= SIMD_32(RC[16-i]);
				
				A1.rotate_left(1);
				A2.rotate_left(5);
				A3.rotate_left(2);
				
				mixin(NOK_SIMD_GAMMA());
				
				A1.rotate_right(1);
				A2.rotate_right(5);
				A3.rotate_right(2);
			}
			
			mixin(NOK_SIMD_THETA());
			A0 ^= SIMD_32(RC[0]);
			
			SIMD_32.transpose(A0, A1, A2, A3);
			
			A0.store_be(output);
			A1.store_be(output + 16);
			A2.store_be(output + 32);
			A3.store_be(output + 48);
			
			input += 64;
			output += 64;
			blocks -= 4;
		}
		
		if (blocks)
			super.decrypt_n(input, output, blocks);
	}

	BlockCipher clone() const { return new Noekeon_SIMD; }
}

/*
* Noekeon's Theta Operation
*/
string NOK_SIMD_THETA() {
	return `{SIMD_32 T = A0 ^ A2;
	SIMD_32 T_l8 = T;
	SIMD_32 T_r8 = T;
	T_l8.rotate_left(8);
	T_r8.rotate_right(8);
	T ^= T_l8;
	T ^= T_r8;
	A1 ^= T;			
	A3 ^= T;
	A0 ^= K0;				
	A1 ^= K1;				
	A2 ^= K2;				
	A3 ^= K3;
	T = A1 ^ A3;			
	T_l8 = T;				
	T_r8 = T;				
	T_l8.rotate_left(8);
	T_r8.rotate_right(8);
	T ^= T_l8;
	T ^= T_r8;
	A0 ^= T;			
	A2 ^= T;}`;			
} 

/*
* Noekeon's Gamma S-Box Layer
*/
string NOK_SIMD_GAMMA() {
	return `{A1 ^= A3.andc(~A2);
	A0 ^= A2 & A1;
	SIMD_32 T = A3;
	A3 = A0;
	A0 = T;
	A2 ^= A0 ^ A1 ^ A3;
	A1 ^= A3.andc(~A2);
	A0 ^= A2 & A1;}`;
}