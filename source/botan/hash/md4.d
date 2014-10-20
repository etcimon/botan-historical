/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.md4;

import botan.hash.mdx_hash;
import botan.utils.loadstor;
import botan.utils.rotate;
/**
* MD4
*/
class MD4 : MDx_HashFunction
{
public:
	string name() const { return "MD4"; }
	size_t output_length() const { return 16; }
	HashFunction clone() const { return new MD4; }

	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		super.clear();
		zeroise(M);
		digest[0] = 0x67452301;
		digest[1] = 0xEFCDAB89;
		digest[2] = 0x98BADCFE;
		digest[3] = 0x10325476;
	}

	this()
	{  
		super(64, false, true);
		M = 16;
		digest = 4;
		clear(); 
	}
package:
	/*
	* MD4 Compression Function
	*/
	void compress_n(in ubyte* input, size_t blocks)
	{
		uint A = digest[0], B = digest[1], C = digest[2], D = digest[3];
		
		for (size_t i = 0; i != blocks; ++i)
		{
			load_le(&M[0], input, M.length);
			
			FF(A,B,C,D,M[ 0], 3);	FF(D,A,B,C,M[ 1], 7);
			FF(C,D,A,B,M[ 2],11);	FF(B,C,D,A,M[ 3],19);
			FF(A,B,C,D,M[ 4], 3);	FF(D,A,B,C,M[ 5], 7);
			FF(C,D,A,B,M[ 6],11);	FF(B,C,D,A,M[ 7],19);
			FF(A,B,C,D,M[ 8], 3);	FF(D,A,B,C,M[ 9], 7);
			FF(C,D,A,B,M[10],11);	FF(B,C,D,A,M[11],19);
			FF(A,B,C,D,M[12], 3);	FF(D,A,B,C,M[13], 7);
			FF(C,D,A,B,M[14],11);	FF(B,C,D,A,M[15],19);
			
			GG(A,B,C,D,M[ 0], 3);	GG(D,A,B,C,M[ 4], 5);
			GG(C,D,A,B,M[ 8], 9);	GG(B,C,D,A,M[12],13);
			GG(A,B,C,D,M[ 1], 3);	GG(D,A,B,C,M[ 5], 5);
			GG(C,D,A,B,M[ 9], 9);	GG(B,C,D,A,M[13],13);
			GG(A,B,C,D,M[ 2], 3);	GG(D,A,B,C,M[ 6], 5);
			GG(C,D,A,B,M[10], 9);	GG(B,C,D,A,M[14],13);
			GG(A,B,C,D,M[ 3], 3);	GG(D,A,B,C,M[ 7], 5);
			GG(C,D,A,B,M[11], 9);	GG(B,C,D,A,M[15],13);
			
			HH(A,B,C,D,M[ 0], 3);	HH(D,A,B,C,M[ 8], 9);
			HH(C,D,A,B,M[ 4],11);	HH(B,C,D,A,M[12],15);
			HH(A,B,C,D,M[ 2], 3);	HH(D,A,B,C,M[10], 9);
			HH(C,D,A,B,M[ 6],11);	HH(B,C,D,A,M[14],15);
			HH(A,B,C,D,M[ 1], 3);	HH(D,A,B,C,M[ 9], 9);
			HH(C,D,A,B,M[ 5],11);	HH(B,C,D,A,M[13],15);
			HH(A,B,C,D,M[ 3], 3);	HH(D,A,B,C,M[11], 9);
			HH(C,D,A,B,M[ 7],11);	HH(B,C,D,A,M[15],15);
			
			A = (digest[0] += A);
			B = (digest[1] += B);
			C = (digest[2] += C);
			D = (digest[3] += D);
			
			input += hash_block_size();
		}
	}

	/*
	* Copy out the digest
	*/
	void copy_out(ubyte* output)
	{
		for (size_t i = 0; i != output_length(); i += 4)
			store_le(digest[i/4], output + i);
	}

	/**
	* The message buffer, exposed for use by subclasses (x86 asm)
	*/
	SafeVector!uint M;

	/**
	* The digest value, exposed for use by subclasses (x86 asm)
	*/
	SafeVector!uint digest;
};

private:

/*
* MD4 FF Function
*/
void FF(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
	A += (D ^ (B & (C ^ D))) + M;
	A  = rotate_left(A, S);
}

/*
* MD4 GG Function
*/
void GG(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
	A += ((B & C) | (D & (B | C))) + M + 0x5A827999;
	A  = rotate_left(A, S);
}

/*
* MD4 HH Function
*/
void HH(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
	A += (B ^ C ^ D) + M + 0x6ED9EBA1;
	A  = rotate_left(A, S);
}