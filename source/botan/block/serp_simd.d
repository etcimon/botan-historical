/*
* Serpent (SIMD)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.serp_simd;

import botan.simd.simd_32;
import botan.utils.loadstor;
import botan.block.serpent;
/**
* Serpent implementation using SIMD
*/
final class Serpent_SIMD : Serpent
{
public:
	override @property size_t parallelism() const { return 4; }

	/*
	* Serpent Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const uint* KS = &(this.get_round_keys()[0]);
		
		while(blocks >= 4)
		{
			serpent_encrypt_4(input, output, KS);
			input += 4 * BLOCK_SIZE;
			output += 4 * BLOCK_SIZE;
			blocks -= 4;
		}
		
		if (blocks)
			super.encrypt_n(input, output, blocks);
	}

	/*
	* Serpent Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const uint* KS = &(this.get_round_keys()[0]);
		
		while(blocks >= 4)
		{
			serpent_decrypt_4(input, output, KS);
			input += 4 * BLOCK_SIZE;
			output += 4 * BLOCK_SIZE;
			blocks -= 4;
		}
		
		if (blocks)
			super.decrypt_n(input, output, blocks);
	}

	BlockCipher clone() const { return new Serpent_SIMD; }
};

protected:

/*
* SIMD Serpent Encryption of 4 blocks in parallel
*/
void serpent_encrypt_4(const ubyte[64]* input,
					   ubyte[64]* output,
						const uint[132]* keys) pure
{
	SIMD_32 B0 = SIMD_32.load_le(input);
	SIMD_32 B1 = SIMD_32.load_le(input + 16);
	SIMD_32 B2 = SIMD_32.load_le(input + 32);
	SIMD_32 B3 = SIMD_32.load_le(input + 48);
	
	SIMD_32.transpose(B0, B1, B2, B3);
	
	mixin(key_xor!( 0)()); SBoxE1(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 1)()); SBoxE2(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 2)()); SBoxE3(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 3)()); SBoxE4(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 4)()); SBoxE5(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 5)()); SBoxE6(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 6)()); SBoxE7(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 7)()); SBoxE8(B0,B1,B2,B3); mixin(transform());
	
	mixin(key_xor!( 8)()); SBoxE1(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!( 9)()); SBoxE2(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(10)()); SBoxE3(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(11)()); SBoxE4(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(12)()); SBoxE5(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(13)()); SBoxE6(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(14)()); SBoxE7(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(15)()); SBoxE8(B0,B1,B2,B3); mixin(transform());
	
	mixin(key_xor!(16)()); SBoxE1(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(17)()); SBoxE2(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(18)()); SBoxE3(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(19)()); SBoxE4(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(20)()); SBoxE5(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(21)()); SBoxE6(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(22)()); SBoxE7(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(23)()); SBoxE8(B0,B1,B2,B3); mixin(transform());
	
	mixin(key_xor!(24)()); SBoxE1(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(25)()); SBoxE2(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(26)()); SBoxE3(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(27)()); SBoxE4(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(28)()); SBoxE5(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(29)()); SBoxE6(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(30)()); SBoxE7(B0,B1,B2,B3); mixin(transform());
	mixin(key_xor!(31)()); SBoxE8(B0,B1,B2,B3); mixin(key_xor!(32)());
	
	SIMD_32.transpose(B0, B1, B2, B3);
	
	B0.store_le(output);
	B1.store_le(output + 16);
	B2.store_le(output + 32);
	B3.store_le(output + 48);
}

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
void serpent_decrypt_4(const ubyte[64]* input,
					   ubyte[64]* output,
						const uint[132]* keys) pure 
{
	SIMD_32 B0 = SIMD_32.load_le(input);
	SIMD_32 B1 = SIMD_32.load_le(input + 16);
	SIMD_32 B2 = SIMD_32.load_le(input + 32);
	SIMD_32 B3 = SIMD_32.load_le(input + 48);
	
	SIMD_32.transpose(B0, B1, B2, B3);
	
	mixin(key_xor!(32)());  mixin(SBoxD8()); mixin(key_xor!(31)());
	mixin(i_transform()); mixin(SBoxD7()); mixin(key_xor!(30)());
	mixin(i_transform()); mixin(SBoxD6()); mixin(key_xor!(29)());
	mixin(i_transform()); mixin(SBoxD5()); mixin(key_xor!(28)());
	mixin(i_transform()); mixin(SBoxD4()); mixin(key_xor!(27)());
	mixin(i_transform()); mixin(SBoxD3()); mixin(key_xor!(26)());
	mixin(i_transform()); mixin(SBoxD2()); mixin(key_xor!(25)());
	mixin(i_transform()); mixin(SBoxD1()); mixin(key_xor!(24)());
	
	mixin(i_transform()); mixin(SBoxD8()); mixin(key_xor!(23)());
	mixin(i_transform()); mixin(SBoxD7()); mixin(key_xor!(22)());
	mixin(i_transform()); mixin(SBoxD6()); mixin(key_xor!(21)());
	mixin(i_transform()); mixin(SBoxD5()); mixin(key_xor!(20)());
	mixin(i_transform()); mixin(SBoxD4()); mixin(key_xor!(19)());
	mixin(i_transform()); mixin(SBoxD3()); mixin(key_xor!(18)());
	mixin(i_transform()); mixin(SBoxD2()); mixin(key_xor!(17)());
	mixin(i_transform()); mixin(SBoxD1()); mixin(key_xor!(16)());
	
	mixin(i_transform()); mixin(SBoxD8()); mixin(key_xor!(15)());
	mixin(i_transform()); mixin(SBoxD7()); mixin(key_xor!(14)());
	mixin(i_transform()); mixin(SBoxD6()); mixin(key_xor!(13)());
	mixin(i_transform()); mixin(SBoxD5()); mixin(key_xor!(12)());
	mixin(i_transform()); mixin(SBoxD4()); mixin(key_xor!(11)());
	mixin(i_transform()); mixin(SBoxD3()); mixin(key_xor!(10)());
	mixin(i_transform()); mixin(SBoxD2()); mixin(key_xor!( 9)());
	mixin(i_transform()); mixin(SBoxD1()); mixin(key_xor!( 8)());
	
	mixin(i_transform()); mixin(SBoxD8()); mixin(key_xor!( 7)());
	mixin(i_transform()); mixin(SBoxD7()); mixin(key_xor!( 6)());
	mixin(i_transform()); mixin(SBoxD6()); mixin(key_xor!( 5)());
	mixin(i_transform()); mixin(SBoxD5()); mixin(key_xor!( 4)());
	mixin(i_transform()); mixin(SBoxD4()); mixin(key_xor!( 3)());
	mixin(i_transform()); mixin(SBoxD3()); mixin(key_xor!( 2)());
	mixin(i_transform()); mixin(SBoxD2()); mixin(key_xor!( 1)());
	mixin(i_transform()); mixin(SBoxD1()); mixin(key_xor!( 0)());
	
	SIMD_32.transpose(B0, B1, B2, B3);
	
	B0.store_le(output);
	B1.store_le(output + 16);
	B2.store_le(output + 32);
	B3.store_le(output + 48);
}

private:

/*
* Serpent's linear transformations
*/
string transform()
{
	return `B0.rotate_left(13);				
			B2.rotate_left(3);
			B1 ^= B0 ^ B2;
			B3 ^= B2 ^ (B0 << 3);
			B1.rotate_left(1);
			B3.rotate_left(7);
			B0 ^= B1 ^ B3;
			B2 ^= B3 ^ (B1 << 7);
			B0.rotate_left(5);
			B2.rotate_left(22);`;
}

string i_transform()
{
	return `B2.rotate_right(22);
			B0.rotate_right(5);
			B2 ^= B3 ^ (B1 << 7);
			B0 ^= B1 ^ B3;
			B3.rotate_right(7);
			B1.rotate_right(1);
			B3 ^= B2 ^ (B0 << 3);
			B1 ^= B0 ^ B2;
			B2.rotate_right(3);
			B0.rotate_right(13);`;
}

string key_xor(uint round)()
{
	return `B0 ^= SIMD_32(keys[4*` ~ round.stringof ~ `  ]);
			B1 ^= SIMD_32(keys[4*` ~ round.stringof ~ `+1]);
			B2 ^= SIMD_32(keys[4*` ~ round.stringof ~ `+2]);
			B3 ^= SIMD_32(keys[4*` ~ round.stringof ~ `+3]);`;
}