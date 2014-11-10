/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.gost_28147;

import botan.constants;
static if (BOTAN_HAS_GOST_28147_89):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.exceptn;

/**
* The GOST 28147-89 block cipher uses a set of 4 bit Sboxes, however
* the standard does not actually define these Sboxes; they are
* considered a local configuration issue. Several different sets are
* used.
*/
final class GOST_28147_89_Params
{
public:
	/**
	* @param row the row
	* @param col the column
	* @return sbox entry at this row/column
	*/
	ubyte sbox_entry(size_t row, size_t col) const
	{
		ubyte x = sboxes[4 * col + (row / 2)];
		
		return (row % 2 == 0) ? (x >> 4) : (x & 0x0F);
	}

	/**
	* @return name of this parameter set
	*/
	string param_name() const { return name; }

	/**
	* Default GOST parameters are the ones given in GOST R 34.11 for
	* testing purposes; these sboxes are also used by Crypto++, and,
	* at least according to Wikipedia, the Central Bank of Russian
	* Federation
	* @param name of the parameter set
	*/
	this(in string _name = "R3411_94_TestParam") 
	{
		name = _name;
		// Encoded in the packed fromat from RFC 4357
		
		// GostR3411_94_TestParamSet (OID 1.2.643.2.2.31.0)
		__gshared immutable ubyte[64] GOST_R_3411_TEST_PARAMS = [
			0x4E, 0x57, 0x64, 0xD1, 0xAB, 0x8D, 0xCB, 0xBF, 0x94, 0x1A, 0x7A,
			0x4D, 0x2C, 0xD1, 0x10, 0x10, 0xD6, 0xA0, 0x57, 0x35, 0x8D, 0x38,
			0xF2, 0xF7, 0x0F, 0x49, 0xD1, 0x5A, 0xEA, 0x2F, 0x8D, 0x94, 0x62,
			0xEE, 0x43, 0x09, 0xB3, 0xF4, 0xA6, 0xA2, 0x18, 0xC6, 0x98, 0xE3,
			0xC1, 0x7C, 0xE5, 0x7E, 0x70, 0x6B, 0x09, 0x66, 0xF7, 0x02, 0x3C,
			0x8B, 0x55, 0x95, 0xBF, 0x28, 0x39, 0xB3, 0x2E, 0xCC ];
		
		// GostR3411-94-CryptoProParamSet (OID 1.2.643.2.2.31.1)
		__gshared immutable ubyte[64] GOST_R_3411_CRYPTOPRO_PARAMS = [
			0xA5, 0x74, 0x77, 0xD1, 0x4F, 0xFA, 0x66, 0xE3, 0x54, 0xC7, 0x42,
			0x4A, 0x60, 0xEC, 0xB4, 0x19, 0x82, 0x90, 0x9D, 0x75, 0x1D, 0x4F,
			0xC9, 0x0B, 0x3B, 0x12, 0x2F, 0x54, 0x79, 0x08, 0xA0, 0xAF, 0xD1,
			0x3E, 0x1A, 0x38, 0xC7, 0xB1, 0x81, 0xC6, 0xE6, 0x56, 0x05, 0x87,
			0x03, 0x25, 0xEB, 0xFE, 0x9C, 0x6D, 0xF8, 0x6D, 0x2E, 0xAB, 0xDE,
			0x20, 0xBA, 0x89, 0x3C, 0x92, 0xF8, 0xD3, 0x53, 0xBC ];
		
		if (name == "R3411_94_TestParam")
			sboxes = GOST_R_3411_TEST_PARAMS;
		else if (name == "R3411_CryptoPro")
			sboxes = GOST_R_3411_CRYPTOPRO_PARAMS;
		else
			throw new Invalid_Argument("GOST_28147_89_Params: Unknown " ~ name);
	}
private:
	const ubyte* sboxes;
	string name;
};

/**
* GOST 28147-89
*/
final class GOST_28147_89 : Block_Cipher_Fixed_Params!(8, 32)
{
public:

	/*
	* GOST Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint N1 = load_le!uint(input, 0);
			uint N2 = load_le!uint(input, 1);
			
			for (size_t j = 0; j != 3; ++j)
			{
				mixin(GOST_2ROUND!(N1, N2, 0, 1)());
				mixin(GOST_2ROUND!(N1, N2, 2, 3)());
				mixin(GOST_2ROUND!(N1, N2, 4, 5)());
				mixin(GOST_2ROUND!(N1, N2, 6, 7)());
			}
			
			mixin(GOST_2ROUND!(N1, N2, 7, 6)());
			mixin(GOST_2ROUND!(N1, N2, 5, 4)());
			mixin(GOST_2ROUND!(N1, N2, 3, 2)());
			mixin(GOST_2ROUND!(N1, N2, 1, 0)());
			
			store_le(output, N2, N1);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/*
	* GOST Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			uint N1 = load_le!uint(input, 0);
			uint N2 = load_le!uint(input, 1);
			
			mixin(GOST_2ROUND!(N1, N2, 0, 1)());
			mixin(GOST_2ROUND!(N1, N2, 2, 3)());
			mixin(GOST_2ROUND!(N1, N2, 4, 5)());
			mixin(GOST_2ROUND!(N1, N2, 6, 7)());
			
			for (size_t j = 0; j != 3; ++j)
			{
				mixin(GOST_2ROUND!(N1, N2, 7, 6)());
				mixin(GOST_2ROUND!(N1, N2, 5, 4)());
				mixin(GOST_2ROUND!(N1, N2, 3, 2)());
				mixin(GOST_2ROUND!(N1, N2, 1, 0)());
			}
			
			store_le(output, N2, N1);
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	void clear()
	{
		zap(EK);
	}

	@property string name() const
	{
		/*
	'Guess' the right name for the sbox on the basis of the values.
	This would need to be updated if support for other sbox parameters
	is added. Preferably, we would just store the string value in the
	constructor, but can't break binary compat.
	*/
		string sbox_name = "";
		if (SBOX[0] == 0x00072000)
			sbox_name = "R3411_94_TestParam";
		else if (SBOX[0] == 0x0002D000)
			sbox_name = "R3411_CryptoPro";
		else
			throw new Internal_Error("GOST-28147 unrecognized sbox value");
		
		return "GOST-28147-89(" ~ sbox_name ~ ")";
	}

	BlockCipher clone() const { return new GOST_28147_89(SBOX); }

	/**
	* @param params the sbox parameters to use
	*/
	this(in GOST_28147_89_Params param)
	{
		SBOX = 1024;
		// Convert the parallel 4x4 sboxes into larger word-based sboxes
		for (size_t i = 0; i != 4; ++i)
			for (size_t j = 0; j != 256; ++j)
		{
			const uint T = (param.sbox_entry(2*i  , j % 16)) |
				(param.sbox_entry(2*i+1, j / 16) << 4);
			SBOX[256*i+j] = rotate_left(T, (11+8*i) % 32);
		}
	}
private:
	this(in Vector!uint other_SBOX) {
		SBOX = other_SBOX; 
		EK = 8;
	}

	/*
	* GOST Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		EK.resize(8);
		for (size_t i = 0; i != 8; ++i)
			EK[i] = load_le!uint(key, i);
	}

	/*
	* The sbox is not secret, this is just a larger expansion of it
	* which we generate at runtime for faster execution
	*/
	Vector!uint SBOX;

	Secure_Vector!uint EK;
};

protected:

/*
* Two rounds of GOST
*/
string GOST_2ROUND(alias N1, alias N2, ubyte R1, ubyte R2)()
{
	const N1_ = __traits(identifier, N1).stringof;
	const N2_ = __traits(identifier, N2).stringof;
	return `{
			uint T0 = ` ~ N1_ ~ ` + EK[` ~ R1.stringof ~ `];
			N2 ^= SBOX[get_byte(3, T0)] |
				SBOX[get_byte(2, T0)+256] | 
				SBOX[get_byte(1, T0)+512] | 
				SBOX[get_byte(0, T0)+768];

			uint T1 = ` ~ N2 ~ ` + EK[` ~ R2.stringof ~ `];
			N1 ^= SBOX[get_byte(3, T1)] |
				SBOX[get_byte(2, T1)+256] |
				SBOX[get_byte(1, T1)+512] |
				SBOX[get_byte(0, T1)+768];
		}`;
}
