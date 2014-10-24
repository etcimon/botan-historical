/*
* SHA-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.sha160;

import botan.constants;
static if (BOTAN_HAS_SHA1):

import botan.hash.mdx_hash;

import botan.utils.loadstor;
import botan.utils.rotate;

/**
* NIST's SHA-160
*/
class SHA_160 : MDx_HashFunction
{
public:
	final override @property string name() const { return "SHA-160"; }
	final @property size_t output_length() const { return 20; }
	HashFunction clone() const { return new SHA_160; }

	/*
	* Clear memory of sensitive data
	*/
	final void clear()
	{
		super.clear();
		zeroise(W);
		digest[0] = 0x67452301;
		digest[1] = 0xEFCDAB89;
		digest[2] = 0x98BADCFE;
		digest[3] = 0x10325476;
		digest[4] = 0xC3D2E1F0;
	}

	this()
	{
		super(64, true, true);
		digest = 5;
		W = 80;
		clear();
	}
protected:
	/**
	* Set a custom size for the W array. Normally 80, but some
	* subclasses need slightly more for best performance/internal
	* constraints
	* @param W_size how big to make W
	*/
	this(size_t W_size) 
	{
		super(64, true, true);
		digest = 5;
		W = W_size;
		clear();
	}

	/*
	* SHA-160 Compression Function
	*/
	void compress_n(in ubyte* input, size_t blocks)
	{
		uint A = digest[0], B = digest[1], C = digest[2],
			D = digest[3], E = digest[4];
		
		for (size_t i = 0; i != blocks; ++i)
		{
			load_be(&W[0], input, 16);
			
			for (size_t j = 16; j != 80; j += 8)
			{
				W[j  ] = rotate_left((W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16]), 1);
				W[j+1] = rotate_left((W[j-2] ^ W[j-7] ^ W[j-13] ^ W[j-15]), 1);
				W[j+2] = rotate_left((W[j-1] ^ W[j-6] ^ W[j-12] ^ W[j-14]), 1);
				W[j+3] = rotate_left((W[j  ] ^ W[j-5] ^ W[j-11] ^ W[j-13]), 1);
				W[j+4] = rotate_left((W[j+1] ^ W[j-4] ^ W[j-10] ^ W[j-12]), 1);
				W[j+5] = rotate_left((W[j+2] ^ W[j-3] ^ W[j- 9] ^ W[j-11]), 1);
				W[j+6] = rotate_left((W[j+3] ^ W[j-2] ^ W[j- 8] ^ W[j-10]), 1);
				W[j+7] = rotate_left((W[j+4] ^ W[j-1] ^ W[j- 7] ^ W[j- 9]), 1);
			}
			
			F1(A, B, C, D, E, W[ 0]);	F1(E, A, B, C, D, W[ 1]);
			F1(D, E, A, B, C, W[ 2]);	F1(C, D, E, A, B, W[ 3]);
			F1(B, C, D, E, A, W[ 4]);	F1(A, B, C, D, E, W[ 5]);
			F1(E, A, B, C, D, W[ 6]);	F1(D, E, A, B, C, W[ 7]);
			F1(C, D, E, A, B, W[ 8]);	F1(B, C, D, E, A, W[ 9]);
			F1(A, B, C, D, E, W[10]);	F1(E, A, B, C, D, W[11]);
			F1(D, E, A, B, C, W[12]);	F1(C, D, E, A, B, W[13]);
			F1(B, C, D, E, A, W[14]);	F1(A, B, C, D, E, W[15]);
			F1(E, A, B, C, D, W[16]);	F1(D, E, A, B, C, W[17]);
			F1(C, D, E, A, B, W[18]);	F1(B, C, D, E, A, W[19]);
			
			F2(A, B, C, D, E, W[20]);	F2(E, A, B, C, D, W[21]);
			F2(D, E, A, B, C, W[22]);	F2(C, D, E, A, B, W[23]);
			F2(B, C, D, E, A, W[24]);	F2(A, B, C, D, E, W[25]);
			F2(E, A, B, C, D, W[26]);	F2(D, E, A, B, C, W[27]);
			F2(C, D, E, A, B, W[28]);	F2(B, C, D, E, A, W[29]);
			F2(A, B, C, D, E, W[30]);	F2(E, A, B, C, D, W[31]);
			F2(D, E, A, B, C, W[32]);	F2(C, D, E, A, B, W[33]);
			F2(B, C, D, E, A, W[34]);	F2(A, B, C, D, E, W[35]);
			F2(E, A, B, C, D, W[36]);	F2(D, E, A, B, C, W[37]);
			F2(C, D, E, A, B, W[38]);	F2(B, C, D, E, A, W[39]);
			
			F3(A, B, C, D, E, W[40]);	F3(E, A, B, C, D, W[41]);
			F3(D, E, A, B, C, W[42]);	F3(C, D, E, A, B, W[43]);
			F3(B, C, D, E, A, W[44]);	F3(A, B, C, D, E, W[45]);
			F3(E, A, B, C, D, W[46]);	F3(D, E, A, B, C, W[47]);
			F3(C, D, E, A, B, W[48]);	F3(B, C, D, E, A, W[49]);
			F3(A, B, C, D, E, W[50]);	F3(E, A, B, C, D, W[51]);
			F3(D, E, A, B, C, W[52]);	F3(C, D, E, A, B, W[53]);
			F3(B, C, D, E, A, W[54]);	F3(A, B, C, D, E, W[55]);
			F3(E, A, B, C, D, W[56]);	F3(D, E, A, B, C, W[57]);
			F3(C, D, E, A, B, W[58]);	F3(B, C, D, E, A, W[59]);
			
			F4(A, B, C, D, E, W[60]);	F4(E, A, B, C, D, W[61]);
			F4(D, E, A, B, C, W[62]);	F4(C, D, E, A, B, W[63]);
			F4(B, C, D, E, A, W[64]);	F4(A, B, C, D, E, W[65]);
			F4(E, A, B, C, D, W[66]);	F4(D, E, A, B, C, W[67]);
			F4(C, D, E, A, B, W[68]);	F4(B, C, D, E, A, W[69]);
			F4(A, B, C, D, E, W[70]);	F4(E, A, B, C, D, W[71]);
			F4(D, E, A, B, C, W[72]);	F4(C, D, E, A, B, W[73]);
			F4(B, C, D, E, A, W[74]);	F4(A, B, C, D, E, W[75]);
			F4(E, A, B, C, D, W[76]);	F4(D, E, A, B, C, W[77]);
			F4(C, D, E, A, B, W[78]);	F4(B, C, D, E, A, W[79]);
			
			A = (digest[0] += A);
			B = (digest[1] += B);
			C = (digest[2] += C);
			D = (digest[3] += D);
			E = (digest[4] += E);
			
			input += hash_block_size;
		}
	}

	/*
	* Copy out the digest
	*/
	final void copy_out(ubyte* output)
	{
		for (size_t i = 0; i != output_length(); i += 4)
			store_be(digest[i/4], output + i);
	}

	/**
	* The digest value, exposed for use by subclasses (asm, SSE2)
	*/
	Secure_Vector!uint digest;

	/**
	* The message buffer, exposed for use by subclasses (asm, SSE2)
	*/
	Secure_Vector!uint W;
};

private:
pure:
/*
* SHA-160 F1 Function
*/
void F1(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
	E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + rotate_left(A, 5);
	B  = rotate_left(B, 30);
}

/*
* SHA-160 F2 Function
*/
void F2(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
	E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotate_left(A, 5);
	B  = rotate_left(B, 30);
}

/*
* SHA-160 F3 Function
*/
void F3(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
	E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + rotate_left(A, 5);
	B  = rotate_left(B, 30);
}

/*
* SHA-160 F4 Function
*/
void F4(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
	E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotate_left(A, 5);
	B  = rotate_left(B, 30);
}