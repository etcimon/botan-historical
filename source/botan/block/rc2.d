/*
* RC2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.rc2;

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.rotate;

/**
* RC2
*/
class RC2 : Block_Cipher_Fixed_Params!(8, 1, 32)
{
public:
	/*
	* RC2 Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			ushort R0 = load_le!ushort(input, 0);
			ushort R1 = load_le!ushort(input, 1);
			ushort R2 = load_le!ushort(input, 2);
			ushort R3 = load_le!ushort(input, 3);
			
			for (size_t j = 0; j != 16; ++j)
			{
				R0 += (R1 & ~R3) + (R2 & R3) + K[4*j];
				R0 = rotate_left(R0, 1);
				
				R1 += (R2 & ~R0) + (R3 & R0) + K[4*j + 1];
				R1 = rotate_left(R1, 2);
				
				R2 += (R3 & ~R1) + (R0 & R1) + K[4*j + 2];
				R2 = rotate_left(R2, 3);
				
				R3 += (R0 & ~R2) + (R1 & R2) + K[4*j + 3];
				R3 = rotate_left(R3, 5);
				
				if (j == 4 || j == 10)
				{
					R0 += K[R3 % 64];
					R1 += K[R0 % 64];
					R2 += K[R1 % 64];
					R3 += K[R2 % 64];
				}
			}
			
			store_le(output, R0, R1, R2, R3);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/*
	* RC2 Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			ushort R0 = load_le!ushort(input, 0);
			ushort R1 = load_le!ushort(input, 1);
			ushort R2 = load_le!ushort(input, 2);
			ushort R3 = load_le!ushort(input, 3);
			
			for (size_t j = 0; j != 16; ++j)
			{
				R3 = rotate_right(R3, 5);
				R3 -= (R0 & ~R2) + (R1 & R2) + K[63 - (4*j + 0)];
				
				R2 = rotate_right(R2, 3);
				R2 -= (R3 & ~R1) + (R0 & R1) + K[63 - (4*j + 1)];
				
				R1 = rotate_right(R1, 2);
				R1 -= (R2 & ~R0) + (R3 & R0) + K[63 - (4*j + 2)];
				
				R0 = rotate_right(R0, 1);
				R0 -= (R1 & ~R3) + (R2 & R3) + K[63 - (4*j + 3)];
				
				if (j == 4 || j == 10)
				{
					R3 -= K[R2 % 64];
					R2 -= K[R1 % 64];
					R1 -= K[R0 % 64];
					R0 -= K[R3 % 64];
				}
			}
			
			store_le(output, R0, R1, R2, R3);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/**
	* Return the code of the effective key bits
	* @param bits key length
	* @return EKB code
	*/
	static ubyte EKB_code(size_t ekb)
	{
		immutable ubyte[256] EKB = {
			0xBD, 0x56, 0xEA, 0xF2, 0xA2, 0xF1, 0xAC, 0x2A, 0xB0, 0x93, 0xD1, 0x9C,
			0x1B, 0x33, 0xFD, 0xD0, 0x30, 0x04, 0xB6, 0xDC, 0x7D, 0xDF, 0x32, 0x4B,
			0xF7, 0xCB, 0x45, 0x9B, 0x31, 0xBB, 0x21, 0x5A, 0x41, 0x9F, 0xE1, 0xD9,
			0x4A, 0x4D, 0x9E, 0xDA, 0xA0, 0x68, 0x2C, 0xC3, 0x27, 0x5F, 0x80, 0x36,
			0x3E, 0xEE, 0xFB, 0x95, 0x1A, 0xFE, 0xCE, 0xA8, 0x34, 0xA9, 0x13, 0xF0,
			0xA6, 0x3F, 0xD8, 0x0C, 0x78, 0x24, 0xAF, 0x23, 0x52, 0xC1, 0x67, 0x17,
			0xF5, 0x66, 0x90, 0xE7, 0xE8, 0x07, 0xB8, 0x60, 0x48, 0xE6, 0x1E, 0x53,
			0xF3, 0x92, 0xA4, 0x72, 0x8C, 0x08, 0x15, 0x6E, 0x86, 0x00, 0x84, 0xFA,
			0xF4, 0x7F, 0x8A, 0x42, 0x19, 0xF6, 0xDB, 0xCD, 0x14, 0x8D, 0x50, 0x12,
			0xBA, 0x3C, 0x06, 0x4E, 0xEC, 0xB3, 0x35, 0x11, 0xA1, 0x88, 0x8E, 0x2B,
			0x94, 0x99, 0xB7, 0x71, 0x74, 0xD3, 0xE4, 0xBF, 0x3A, 0xDE, 0x96, 0x0E,
			0xBC, 0x0A, 0xED, 0x77, 0xFC, 0x37, 0x6B, 0x03, 0x79, 0x89, 0x62, 0xC6,
			0xD7, 0xC0, 0xD2, 0x7C, 0x6A, 0x8B, 0x22, 0xA3, 0x5B, 0x05, 0x5D, 0x02,
			0x75, 0xD5, 0x61, 0xE3, 0x18, 0x8F, 0x55, 0x51, 0xAD, 0x1F, 0x0B, 0x5E,
			0x85, 0xE5, 0xC2, 0x57, 0x63, 0xCA, 0x3D, 0x6C, 0xB4, 0xC5, 0xCC, 0x70,
			0xB2, 0x91, 0x59, 0x0D, 0x47, 0x20, 0xC8, 0x4F, 0x58, 0xE0, 0x01, 0xE2,
			0x16, 0x38, 0xC4, 0x6F, 0x3B, 0x0F, 0x65, 0x46, 0xBE, 0x7E, 0x2D, 0x7B,
			0x82, 0xF9, 0x40, 0xB5, 0x1D, 0x73, 0xF8, 0xEB, 0x26, 0xC7, 0x87, 0x97,
			0x25, 0x54, 0xB1, 0x28, 0xAA, 0x98, 0x9D, 0xA5, 0x64, 0x6D, 0x7A, 0xD4,
			0x10, 0x81, 0x44, 0xEF, 0x49, 0xD6, 0xAE, 0x2E, 0xDD, 0x76, 0x5C, 0x2F,
			0xA7, 0x1C, 0xC9, 0x09, 0x69, 0x9A, 0x83, 0xCF, 0x29, 0x39, 0xB9, 0xE9,
			0x4C, 0xFF, 0x43, 0xAB };
		
		if (ekb < 256)
			return EKB[ekb];
		else
			throw new Encoding_Error("EKB_code: EKB is too large");
	}

	void clear()
	{
		zap(K);
	}

	string name() const { return "RC2"; }
	BlockCipher clone() const { return new RC2; }
private:
	/*
	* RC2 Key Schedule
	*/
	void key_schedule(in ubyte* key)
	{
		immutable ubyte[256] TABLE = [
			0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79,
				0x4A, 0xA0, 0xD8, 0x9D, 0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
				0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2, 0x17, 0x9A, 0x59, 0xF5,
				0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
				0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22,
				0x5C, 0x6B, 0x4E, 0x82, 0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
				0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC, 0x12, 0x75, 0xCA, 0x1F,
				0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
				0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B,
				0xBC, 0x94, 0x43, 0x03, 0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
				0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7, 0x08, 0xE8, 0xEA, 0xDE,
				0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
				0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E,
				0x04, 0x18, 0xA4, 0xEC, 0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
				0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39, 0x99, 0x7C, 0x3A, 0x85,
				0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
				0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10,
				0x67, 0x6C, 0xBA, 0xC9, 0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
				0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9, 0x0D, 0x38, 0x34, 0x1B,
				0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
				0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68,
			0xFE, 0x7F, 0xC1, 0xAD ];
		
		SafeVector!ubyte L = SafeVector!ubyte(128);
		copy_mem(&L[0], key, length);
		
		for (size_t i = length; i != 128; ++i)
			L[i] = TABLE[(L[i-1] + L[i-length]) % 256];
		
		L[128-length] = TABLE[L[128-length]];
		
		for (int i = 127-length; i >= 0; --i)
			L[i] = TABLE[L[i+1] ^ L[i+length]];
		
		K.resize(64);
		load_le!ushort(&K[0], &L[0], 64);
	}
	SafeVector!ushort K;
};






