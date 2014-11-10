/*
* Threefish
* (C) 2013,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.threefish;

import botan.constants;
static if (BOTAN_HAS_THREEFISH_512):

import botan.utils.rotate;
import botan.utils.loadstor;
import botan.block.block_cipher;

/**
* Threefish-512
*/
class Threefish_512 : Block_Cipher_Fixed_Params!(64, 64)
{
public:
	override void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		assert(m_K.length == 9, "Key was set");
		assert(m_T.length == 3, "Tweak was set");
		
		for (size_t i = 0; i != blocks; ++i)
		{
			ulong X0 = load_le!ulong(input, 0);
			ulong X1 = load_le!ulong(input, 1);
			ulong X2 = load_le!ulong(input, 2);
			ulong X3 = load_le!ulong(input, 3);
			ulong X4 = load_le!ulong(input, 4);
			ulong X5 = load_le!ulong(input, 5);
			ulong X6 = load_le!ulong(input, 6);
			ulong X7 = load_le!ulong(input, 7);
			
			mixin(THREEFISH_ENC_INJECT_KEY!(0)());

			mixin(THREEFISH_ENC_8_ROUNDS!(1,2)());
			mixin(THREEFISH_ENC_8_ROUNDS!(3,4)());
			mixin(THREEFISH_ENC_8_ROUNDS!(5,6)());
			mixin(THREEFISH_ENC_8_ROUNDS!(7,8)());
			mixin(THREEFISH_ENC_8_ROUNDS!(9,10)());
			mixin(THREEFISH_ENC_8_ROUNDS!(11,12)());
			mixin(THREEFISH_ENC_8_ROUNDS!(13,14)());
			mixin(THREEFISH_ENC_8_ROUNDS!(15,16)());
			mixin(THREEFISH_ENC_8_ROUNDS!(17,18)());
			
			store_le(output, X0, X1, X2, X3, X4, X5, X6, X7);
			
			input += 64;
			output += 64;
		}
	}

	override void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		assert(m_K.length == 9, "Key was set");
		assert(m_T.length == 3, "Tweak was set");
		
		for (size_t i = 0; i != blocks; ++i)
		{
			ulong X0 = load_le!ulong(input, 0);
			ulong X1 = load_le!ulong(input, 1);
			ulong X2 = load_le!ulong(input, 2);
			ulong X3 = load_le!ulong(input, 3);
			ulong X4 = load_le!ulong(input, 4);
			ulong X5 = load_le!ulong(input, 5);
			ulong X6 = load_le!ulong(input, 6);
			ulong X7 = load_le!ulong(input, 7);
			
			mixin(THREEFISH_DEC_INJECT_KEY!(18)());

			mixin(THREEFISH_DEC_8_ROUNDS!(17,16)());
			mixin(THREEFISH_DEC_8_ROUNDS!(15,14)());
			mixin(THREEFISH_DEC_8_ROUNDS!(13,12)());
			mixin(THREEFISH_DEC_8_ROUNDS!(11,10)());
			mixin(THREEFISH_DEC_8_ROUNDS!(9,8)());
			mixin(THREEFISH_DEC_8_ROUNDS!(7,6)());
			mixin(THREEFISH_DEC_8_ROUNDS!(5,4)());
			mixin(THREEFISH_DEC_8_ROUNDS!(3,2)());
			mixin(THREEFISH_DEC_8_ROUNDS!(1,0)());
			
			store_le(output, X0, X1, X2, X3, X4, X5, X6, X7);
			
			input += 64;
			output += 64;
		}
	}

	final void set_tweak(in ubyte* tweak, size_t len)
	{
		if (len != 16)
			throw new Exception("Unsupported twofish tweak length");
		m_T[0] = load_le!ulong(tweak, 0);
		m_T[1] = load_le!ulong(tweak, 1);
		m_T[2] = m_T[0] ^ m_T[1];
	}

	override void clear()
	{
		zeroise(m_K);
		zeroise(m_T);
	}

	final override @property string name() const { return "Threefish-512"; }
	override BlockCipher clone() const { return new Threefish_512; }

	this() {
		m_T = 3;
	}

protected:
	final const ref Secure_Vector!ulong get_T() const { return m_T; }
	final const ref Secure_Vector!ulong get_K() const { return m_K; }
private:
	override void key_schedule(in ubyte* key, size_t)
	{
		// todo: define key schedule for smaller keys
		m_K.resize(9);
		
		for (size_t i = 0; i != 8; ++i)
			m_K[i] = load_le!ulong(key, i);
		
		m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
				 m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
	}


	final void skein_feedfwd(in Secure_Vector!ulong M,
	                   			const ref Secure_Vector!ulong T)
	{
		assert(m_K.length == 9, "Key was set");
		assert(M.length == 8, "Single block");
		
		m_T[0] = T[0];
		m_T[1] = T[1];
		m_T[2] = T[0] ^ T[1];
		
		ulong X0 = M[0];
		ulong X1 = M[1];
		ulong X2 = M[2];
		ulong X3 = M[3];
		ulong X4 = M[4];
		ulong X5 = M[5];
		ulong X6 = M[6];
		ulong X7 = M[7];
		
		mixin(THREEFISH_ENC_INJECT_KEY!(0)());

		mixin(THREEFISH_ENC_8_ROUNDS!(1,2)());
		mixin(THREEFISH_ENC_8_ROUNDS!(3,4)());
		mixin(THREEFISH_ENC_8_ROUNDS!(5,6)());
		mixin(THREEFISH_ENC_8_ROUNDS!(7,8)());
		mixin(THREEFISH_ENC_8_ROUNDS!(9,10)());
		mixin(THREEFISH_ENC_8_ROUNDS!(11,12)());
		mixin(THREEFISH_ENC_8_ROUNDS!(13,14)());
		mixin(THREEFISH_ENC_8_ROUNDS!(15,16)());
		mixin(THREEFISH_ENC_8_ROUNDS!(17,18)());
		
		m_K[0] = M[0] ^ X0;
		m_K[1] = M[1] ^ X1;
		m_K[2] = M[2] ^ X2;
		m_K[3] = M[3] ^ X3;
		m_K[4] = M[4] ^ X4;
		m_K[5] = M[5] ^ X5;
		m_K[6] = M[6] ^ X6;
		m_K[7] = M[7] ^ X7;
		
		m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
				 m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
	}

	// Private data
	Secure_Vector!ulong m_T;
	Secure_Vector!ulong m_K;
}

package:


string THREEFISH_ENC_ROUND(alias _X0, alias _X1, alias _X2, alias _X3, 
                           alias _X4, alias _X5, alias _X6, alias _X7, 
                           ubyte _ROT1, ubyte _ROT2, ubyte _ROT3, ubyte _ROT4)()
{
	const X0 = __traits(identifier, _X0).stringof;
	const X1 = __traits(identifier, _X1).stringof;
	const X2 = __traits(identifier, _X2).stringof;
	const X3 = __traits(identifier, _X3).stringof;
	const X4 = __traits(identifier, _X4).stringof;
	const X5 = __traits(identifier, _X5).stringof;
	const X6 = __traits(identifier, _X6).stringof;
	const X7 = __traits(identifier, _X7).stringof;
	const ROT1 = _ROT1.stringof;
	const ROT2 = _ROT2.stringof;
	const ROT3 = _ROT3.stringof;
	const ROT4 = _ROT4.stringof;

	return X0 ~ ` += ` ~ X4 ~ `;
		` ~ X1 ~ ` += ` ~ X5 ~ `;
		` ~ X2 ~ ` += ` ~ X6 ~ `;
		` ~ X3 ~ ` += ` ~ X7 ~ `;
		` ~ X4 ~ ` = rotate_left(` ~ X4 ~ `, ` ~ ROT1 ~ `);
		` ~ X5 ~ ` = rotate_left(` ~ X5 ~ `, ` ~ ROT2 ~ `);
		` ~ X6 ~ ` = rotate_left(` ~ X6 ~ `, ` ~ ROT3 ~ `);
		` ~ X7 ~ ` = rotate_left(` ~ X7 ~ `, ` ~ ROT4 ~ `);
		` ~ X4 ~ ` ^= ` ~ X0 ~ `;
		` ~ X5 ~ ` ^= ` ~ X1 ~ `;
		` ~ X6 ~ ` ^= ` ~ X2 ~ `;
		` ~ X7 ~ ` ^= ` ~ X3 ~ `;`;
}

string THREEFISH_ENC_INJECT_KEY(alias _r)() 
{
	const r = __traits(identifier, _r).stringof;

	return `X0 += m_K[(` ~ r ~ `  ) % 9];
		X1 += m_K[(` ~ r ~ `+1) % 9];
		X2 += m_K[(` ~ r ~ `+2) % 9];
		X3 += m_K[(` ~ r ~ `+3) % 9];
		X4 += m_K[(` ~ r ~ `+4) % 9];
		X5 += m_K[(` ~ r ~ `+5) % 9] + m_T[(` ~ r ~ `  ) % 3];
		X6 += m_K[(` ~ r ~ `+6) % 9] + m_T[(` ~ r ~ `+1) % 3];
		X7 += m_K[(` ~ r ~ `+7) % 9] + (` ~ r ~ `);`;
}

string THREEFISH_ENC_8_ROUNDS(ubyte R1, ubyte R2)()
{
	return `mixin(THREEFISH_ENC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37)());
			mixin(THREEFISH_ENC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42)());
			mixin(THREEFISH_ENC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39)());
			mixin(THREEFISH_ENC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56)());
			mixin(THREEFISH_ENC_INJECT_KEY!(` ~ R1.stringof ~ `)());

			mixin(THREEFISH_ENC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24)());
			mixin(THREEFISH_ENC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17)());
			mixin(THREEFISH_ENC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43)());
			mixin(THREEFISH_ENC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22)());
			mixin(THREEFISH_ENC_INJECT_KEY!(` ~ R2.stringof ~ `)());`;
}

string THREEFISH_DEC_ROUND(alias _X0, alias _X1, alias _X2, alias _X3, 
                           alias _X4, alias _X5, alias _X6, alias _X7, 
                           ubyte _ROT1, ubyte _ROT2, ubyte _ROT3, ubyte _ROT4)()
{
	const X0 = __traits(identifier, _X0).stringof;
	const X1 = __traits(identifier, _X1).stringof;
	const X2 = __traits(identifier, _X2).stringof;
	const X3 = __traits(identifier, _X3).stringof;
	const X4 = __traits(identifier, _X4).stringof;
	const X5 = __traits(identifier, _X5).stringof;
	const X6 = __traits(identifier, _X6).stringof;
	const X7 = __traits(identifier, _X7).stringof;
	const ROT1 = _ROT1.stringof;
	const ROT2 = _ROT2.stringof;
	const ROT3 = _ROT3.stringof;
	const ROT4 = _ROT4.stringof;
	return X4 ~ ` ^= ` ~ X0 ~ `;
		` ~ X5 ~ ` ^= ` ~ X1 ~ `;
		` ~ X6 ~ ` ^= ` ~ X2 ~ `;
		` ~ X7 ~ ` ^= ` ~ X3 ~ `;
		` ~ X4 ~ ` = rotate_right(` ~ X4 ~ `, ` ~ ROT1 ~ `);
		` ~ X5 ~ ` = rotate_right(` ~ X5 ~ `, ` ~ ROT2 ~ `);
		` ~ X6 ~ ` = rotate_right(` ~ X6 ~ `, ` ~ ROT3 ~ `);
		` ~ X7 ~ ` = rotate_right(` ~ X7 ~ `, ` ~ ROT4 ~ `);
		` ~ X0 ~ ` -= ` ~ X4 ~ `;
		` ~ X1 ~ ` -= ` ~ X5 ~ `;
		` ~ X2 ~ ` -= ` ~ X6 ~ `;
		` ~ X3 ~ ` -= ` ~ X7 ~ `;`;
}
	
string THREEFISH_DEC_INJECT_KEY(alias _r)() 
{
	const r = __traits(identifier, _r).stringof;
	return `X0 -= m_K[(` ~ r ~ `  ) % 9];
			X1 -= m_K[(` ~ r ~ `+1) % 9];
			X2 -= m_K[(` ~ r ~ `+2) % 9];
			X3 -= m_K[(` ~ r ~ `+3) % 9];
			X4 -= m_K[(` ~ r ~ `+4) % 9];
			X5 -= m_K[(` ~ r ~ `+5) % 9] + m_T[(` ~ r ~ `  ) % 3];
			X6 -= m_K[(` ~ r ~ `+6) % 9] + m_T[(` ~ r ~ `+1) % 3];
			X7 -= m_K[(` ~ r ~ `+7) % 9] + (` ~ r ~ `);`;
}

void THREEFISH_DEC_8_ROUNDS(ubyte R1, ubyte R2)()
{
	return `mixin(THREEFISH_DEC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22)());
			mixin(THREEFISH_DEC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43)());
			mixin(THREEFISH_DEC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17)());
			mixin(THREEFISH_DEC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24)());
			mixin(THREEFISH_DEC_INJECT_KEY!(` ~ R1.stringof ~ `)());
			
			mixin(THREEFISH_DEC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56)());
			mixin(THREEFISH_DEC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39)());
			mixin(THREEFISH_DEC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42)());
			mixin(THREEFISH_DEC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37)());
			mixin(THREEFISH_DEC_INJECT_KEY!(` ~ R2.stringof ~ `)());`;
}

